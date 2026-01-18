// ==== ENV bootstrap (INTERNAL, do not log secrets) ====
(function bootstrapEnv() {
  try {
    const path = require("path");
    const fs = require("fs");

    // relay/.. = BASE_DIR
    const baseDir = path.resolve(__dirname, "..");

    // ENV_FILE 우선, 없으면 config\\.env.internal
    const envFile = process.env.ENV_FILE
      ? path.resolve(process.env.ENV_FILE)
      : path.join(baseDir, "config", ".env.internal");

    if (fs.existsSync(envFile)) {
      require("dotenv").config({ path: envFile });
      console.log("[GenieSecurity] ENV loaded:", envFile);
    } else {
      console.log("[GenieSecurity] ENV file not found:", envFile);
    }

    // 🔑 단일 소스 원칙: MASTER_KEY 없으면 MASTER_KEY_B64를 매핑
    if (!process.env.MASTER_KEY && process.env.MASTER_KEY_B64) {
      process.env.MASTER_KEY = process.env.MASTER_KEY_B64;
    }
  } catch (e) {
    console.log(
      "[GenieSecurity] ENV bootstrap failed:",
      String(e && e.message ? e.message : e)
    );
  }
})();
// ==== end bootstrap ====

// relay_server/server.cjs
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const os = require("os");
const { evaluatePolicy } = require("./policy/policy_eval.cjs");
const net = require("net");
const { Siem, toEcsEvent } = require("./siem/siem.cjs");
const { computeRisk, loadRiskPolicyFromEnv } = require("./risk/risk_engine.cjs");
const { buildComplianceLines } = require("./compliance/compliance_report.cjs");

// ==========================
// ✅ X25519 (raw key <-> SPKI/PKCS8 DER) helpers
// - server_identity.pub 은 32바이트 RAW(Base64)
// - Node crypto는 SPKI/PKCS8 DER 필요 => prefix로 래핑
// ==========================
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex"); // + 32 bytes pub
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex"); // + 32 bytes priv

// ✅ Ed25519 (raw pub -> SPKI DER) helper for PoP verification (S-1)
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex"); // + 32 bytes pub

function ed25519PublicKeyFromRawB64(pubB64) {
  const raw = Buffer.from(String(pubB64 || ""), "base64");
  if (raw.length !== 32) throw new Error("invalid_ed25519_pub_raw");
  const der = Buffer.concat([ED25519_SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function x25519PublicKeyFromRawB64(pubB64) {
  const raw = Buffer.from(String(pubB64 || ""), "base64");
  if (raw.length !== 32) throw new Error("invalid_x25519_pub_raw");
  const der = Buffer.concat([X25519_SPKI_PREFIX, raw]);
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function x25519PrivateKeyFromRawB64(privB64) {
  const raw = Buffer.from(String(privB64 || ""), "base64");
  if (raw.length !== 32) throw new Error("invalid_x25519_priv_raw");
  const der = Buffer.concat([X25519_PKCS8_PREFIX, raw]);
  return crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function x25519GenEphemeral() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const pubDer = publicKey.export({ format: "der", type: "spki" });
  const pubRaw = pubDer.slice(pubDer.length - 32);
  const privDer = privateKey.export({ format: "der", type: "pkcs8" });
  const privRaw = privDer.slice(privDer.length - 32);
  return { publicKey, privateKey, pubRawB64: bufToB64(pubRaw), privRawB64: bufToB64(privRaw) };
}

function hkdfSha256(ikm, salt, info, len) {
  return crypto.hkdfSync("sha256", ikm, salt, Buffer.from(info, "utf8"), len);
}

function aes256gcmEncrypt(key, plaintextBuf, aadBuf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  if (aadBuf) cipher.setAAD(aadBuf);
  const ciphertext = Buffer.concat([cipher.update(plaintextBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

function aes256gcmDecrypt(key, iv, ciphertext, tag, aadBuf) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  if (aadBuf) decipher.setAAD(aadBuf);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function timingSafeEqualB64(a, b) {
  try {
    const ba = Buffer.from(String(a || ""), "base64");
    const bb = Buffer.from(String(b || ""), "base64");
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch (_) {
    return false;
  }
}


// ==========================
//  ENV 로드 (반드시 최상단에서 확정)
// - 실행 위치가 달라도 __dirname 기준으로 .env를 로드
// ==========================
// ==========================
//  ENV 로드 (반드시 최상단에서 확정)
// - 기본: relay/.env
// - 제품급: ENV_FILE(절대/상대 경로) 지정 시 그 파일을 우선 로드
//   * 상대 경로는 프로젝트 루트(= relay의 상위 폴더) 기준
// ==========================
(() => {
  const dotenv = require("dotenv");
  const projectRoot = path.resolve(__dirname, "..");
  const envFileRaw = (process.env.ENV_FILE || process.env.DOTENV_PATH || "").toString().trim();
  const resolveEnvPath = (p) => {
    if (!p) return "";
    return path.isAbsolute(p) ? p : path.join(projectRoot, p);
  };

  const candidates = [];
  if (envFileRaw) candidates.push(resolveEnvPath(envFileRaw));
  // fallback candidates (do not override explicit ENV_FILE)
  candidates.push(path.join(__dirname, ".env"));
  candidates.push(path.join(projectRoot, ".env"));
  candidates.push(path.join(projectRoot, ".env.internal"));

  for (const c of candidates) {
    try {
      if (c && fs.existsSync(c)) {
        dotenv.config({ path: c });
        console.log(`[GenieSecurity] ENV loaded: ${c}`);
        return;
      }
    } catch (_) {}
  }
})();


// --- Auto-load POLICY_PUBKEY from POLICY_PUBKEY_PATH (PEM -> DER base64) ---
// Purpose: Keep .env minimal and product-safe. If POLICY_PUBKEY is not provided,
// we derive it from POLICY_PUBKEY_PATH so policy signature verification can be strict
// without requiring manual base64 DER conversion.
// NOTE: POLICY_PUBKEY_PATH is expected to be relative to PROJECT ROOT (not relay/).
try {
  if (!process.env.POLICY_PUBKEY && process.env.POLICY_PUBKEY_PATH) {
    const p = String(process.env.POLICY_PUBKEY_PATH || "").trim();
    const projectRoot = path.resolve(__dirname, "..");
    const abs = path.isAbsolute(p) ? p : path.join(projectRoot, p);
    if (p && fs.existsSync(abs)) {
      const pem = fs.readFileSync(abs, "utf8");
      const keyObj = crypto.createPublicKey(pem);
      const der = keyObj.export({ format: "der", type: "spki" });
      process.env.POLICY_PUBKEY = Buffer.from(der).toString("base64");
      console.log(`[GenieSecurity] POLICY_PUBKEY loaded from POLICY_PUBKEY_PATH: ${abs}`);
    } else {
      console.warn(`[GenieSecurity] POLICY_PUBKEY_PATH not found: ${abs}`);
    }
  }
} catch (e) {
  console.warn(
    `[GenieSecurity] Failed to load POLICY_PUBKEY from POLICY_PUBKEY_PATH: ${String(
      e && e.message ? e.message : e
    )}`
  );
}


// ==========================
// ✅ Early core init (must be before any use)
// - Fixes hoisting/TDZ issues: DATA_DIR/app used before declaration in some sections
// ==========================
const ROOT_DIR = path.resolve(__dirname, "..");
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const app = express();

// ==========================
// Deployment mode
// - internal: LAN/localhost
// - secure: internet-facing / tunnel / proxy
// ==========================
const MODE = String(process.env.MODE || "internal").trim().toLowerCase();


// ==========================
// ✅ SIEM (Splunk/Sentinel/QRadar) exporter
// - Non-blocking enqueue in appendAudit
// - Flush in background
// ==========================
const SIEM = new Siem(process.env);
SIEM.start();


const REQUEST_ID_HEADER = "x-gs-request-id";



const ERROR_CATALOG = [
  { code: "invalid_json", http: 400, desc: "Invalid JSON body.", fix: "Verify request body is valid JSON and Content-Type: application/json." },
  { code: "csrf_blocked", http: 403, desc: "CSRF protection blocked request.", fix: "Use same-origin requests from dashboard or include required headers." },
  { code: "missing_xrw", http: 403, desc: "Missing X-Requested-With header.", fix: "Set X-Requested-With: GenieSecurityDashboard for dashboard-origin requests." },
  { code: "unauthorized", http: 401, desc: "Authentication required.", fix: "Log in via /login (OIDC) or ensure session cookie is present." },
  { code: "forbidden", http: 403, desc: "Insufficient privileges for this action.", fix: "Use an account with required role (operator/admin/auditor)." },
  { code: "oidc_required", http: 401, desc: "OIDC login required by policy.", fix: "Enable OIDC login and sign in through the dashboard." },
  { code: "oidc_stepup_required", http: 401, desc: "OIDC step-up (MFA) required by policy.", fix: "Re-authenticate with MFA or satisfy AMR/ACR requirements." },
  { code: "otp_required", http: 401, desc: "OTP required by policy.", fix: "Provide OTP via header x-gs-otp or query ?gs_otp=." },
  { code: "otp_invalid", http: 401, desc: "Invalid OTP.", fix: "Provide current 6-digit OTP from authenticator app; check server time." },
  { code: "totp_secret_missing", http: 500, desc: "TOTP secret missing while TOTP is required.", fix: "Set OPERATOR_TOTP_SECRET in environment (.env)." },
  { code: "internal_error", http: 500, desc: "Unhandled internal error.", fix: "Check relay logs using requestId (x-gs-request-id) and diagnostics bundle." },
];

function sendError(res, status, code, message, req, extra) {
  try {
    res.status(status).json(Object.assign({ ok: false, code, message, requestId: req && req.requestId }, extra || {}));
  } catch {
    // last resort
    res.status(500).json({ ok: false, code: "internal_error", message: "Failed to send error response." });
  }
}

function nowMs(){ return Date.now(); }

function appendStructuredLog(obj){
  try{
    const line = JSON.stringify(obj) + "\n";
    fs.appendFileSync(STRUCTURED_LOG_PATH, line, { encoding: "utf-8" });
  } catch(_){}
}

app.use((req, res, next) => {
  const rid = req.headers[REQUEST_ID_HEADER] ? String(req.headers[REQUEST_ID_HEADER]).slice(0,64) : crypto.randomBytes(8).toString("hex");
  req.requestId = rid;
  res.setHeader(REQUEST_ID_HEADER, rid);
  const t0 = nowMs();
  res.on("finish", () => {
    appendStructuredLog({
      ts: new Date().toISOString(),
      rid,
      ip: req.ip,
      method: req.method,
      path: req.originalUrl ? String(req.originalUrl).split("?")[0] : req.path,
      status: res.statusCode,
      ms: nowMs() - t0,
      user: req.gsUser ? { sub: req.gsUser.sub, email: req.gsUser.email, roles: req.gsUser.roles } : null
    });
  });
  next();
});

// ==========================
// OIDC / Session / RBAC (Super)
// ==========================
const { SessionStore, signCookieValue, verifyCookieValue, randomId: _randomId, nowSec: _nowSecSess } = require("./auth/session_store.cjs");
const { hasAnyRole } = require("./auth/rbac.cjs");
const OIDC = require("./auth/oidc.cjs");

const { verifyTotp } = require("./auth/totp.cjs");
const OIDC_ENABLED = String(process.env.OIDC_ENABLED || "0").trim() === "1";
const REQUIRE_OIDC = String(process.env.REQUIRE_OIDC || "0").trim() === "1";
const REQUIRE_TOTP = String(process.env.REQUIRE_TOTP || "0").trim() === "1";
const OPERATOR_TOTP_SECRET = String(process.env.OPERATOR_TOTP_SECRET || "").trim(); // Base32
const OTP_WINDOW = Number(process.env.TOTP_WINDOW || "1");
const DISABLE_LEGACY_OPERATOR_KEY = String(process.env.DISABLE_LEGACY_OPERATOR_KEY || "0").trim() === "1";

const OIDC_PROVIDER = String(process.env.OIDC_PROVIDER || "entra").trim();
const OIDC_ISSUER = String(process.env.OIDC_ISSUER || "").trim(); // override if needed
const OIDC_CLIENT_ID = String(process.env.OIDC_CLIENT_ID || "").trim();
const OIDC_CLIENT_SECRET = String(process.env.OIDC_CLIENT_SECRET || "").trim();
const OIDC_REDIRECT_URI = String(process.env.OIDC_REDIRECT_URI || "").trim(); // e.g. http://127.0.0.1:3000/oidc/callback
const OIDC_SCOPE = String(process.env.OIDC_SCOPE || "openid profile email").trim();

const SESSION_SECRET = String(process.env.SESSION_SECRET || "").trim(); // REQUIRED when OIDC_ENABLED=1
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || "0").trim() === "1"; // set 1 when https
const COOKIE_NAME = String(process.env.SESSION_COOKIE_NAME || "gs_sess").trim();
const SESSION_TTL_SEC = parseInt(process.env.SESSION_TTL_SEC || "43200", 10); // default 12h

// OIDC_SANITY: fail-fast for misconfig
if (OIDC_ENABLED) {
  if (!SESSION_SECRET) { console.error('[FATAL] OIDC_ENABLED=1 but SESSION_SECRET is missing.'); process.exit(2); }
  if (!OIDC_CLIENT_ID || !OIDC_CLIENT_SECRET) { console.error('[FATAL] OIDC_ENABLED=1 but OIDC_CLIENT_ID/SECRET missing.'); process.exit(2); }
  if (!OIDC_REDIRECT_URI) { console.error('[FATAL] OIDC_ENABLED=1 but OIDC_REDIRECT_URI missing.'); process.exit(2); }
  if (!OIDC_ISSUER) { console.error('[FATAL] OIDC_ENABLED=1 but OIDC_ISSUER missing.'); process.exit(2); }
}
if (REQUIRE_OIDC && !OIDC_ENABLED) { console.error('[FATAL] REQUIRE_OIDC=1 but OIDC_ENABLED=0.'); process.exit(2); }


// Fail-fast OIDC validation (product-grade)
function _oidcFatal(msg){ console.error('[FATAL] ' + msg); process.exit(2); }
if (OIDC_ENABLED) {
  if (!SESSION_SECRET) _oidcFatal('OIDC_ENABLED=1 requires SESSION_SECRET (cookie signing).');
  if (!OIDC_CLIENT_ID) _oidcFatal('OIDC_ENABLED=1 requires OIDC_CLIENT_ID.');
  if (!OIDC_CLIENT_SECRET) _oidcFatal('OIDC_ENABLED=1 requires OIDC_CLIENT_SECRET.');
  if (!OIDC_REDIRECT_URI) _oidcFatal('OIDC_ENABLED=1 requires OIDC_REDIRECT_URI.');
  if (!OIDC_ISSUER) _oidcFatal('OIDC_ENABLED=1 requires OIDC_ISSUER.');
}
if (REQUIRE_OIDC && !OIDC_ENABLED) {
  _oidcFatal('REQUIRE_OIDC=1 but OIDC_ENABLED=0.');
}
const AUTH_SESSIONS_PATH = path.join(DATA_DIR, "auth_sessions.json");
const sessionStore = new SessionStore({ filePath: AUTH_SESSIONS_PATH, sessionTtlSec: SESSION_TTL_SEC });

// OIDC transient state store (in-memory, short TTL)
const oidcStateMap = new Map(); // state -> { nonce, createdAt }
function oidcPutState(state, nonce, pkceVerifier) { oidcStateMap.set(state, { nonce, pkceVerifier, createdAt: _nowSecSess() }); }
function oidcPopState(state) {
  const v = oidcStateMap.get(state);
  oidcStateMap.delete(state);
  return v || null;
}
function oidcGcState() {
  const now = _nowSecSess();
  for (const [k, v] of oidcStateMap.entries()) {
    if (!v || !v.createdAt || (now - v.createdAt) > 600) oidcStateMap.delete(k); // 10 min
  }
}

function parseCookies(req) {
  const h = req.headers["cookie"];
  const out = {};
  if (!h) return out;
  const parts = String(h).split(";");
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i < 0) continue;
    const k = p.slice(0, i).trim();
    const v = p.slice(i + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const parts = [];
  parts.push(`${name}=${encodeURIComponent(value)}`);
  parts.push(`Path=/`);
  parts.push(`HttpOnly`);
  parts.push(`SameSite=Lax`);
  if (opts.maxAgeSec != null) parts.push(`Max-Age=${opts.maxAgeSec}`);
  if (COOKIE_SECURE) parts.push(`Secure`);
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${COOKIE_SECURE ? "; Secure" : ""}`);
}

function buildUserFromIdTokenPayload(payload, roles) {
  return {
    sub: payload.sub,
    name: payload.name || payload.preferred_username || payload.email || payload.upn || "",
    email: payload.email || payload.preferred_username || payload.upn || "",
    tid: payload.tid || "",
    roles: roles || [],
    iss: payload.iss || "",
    aud: payload.aud || "",
    amr: payload.amr || [],
    acr: payload.acr || "",
  };
}

// attach req.user (OIDC session) if exists
app.use((req, _res, next) => {
  try {
    sessionStore.gc();
    oidcGcState();
    const cookies = parseCookies(req);
    const cv = cookies[COOKIE_NAME];
    if (cv && SESSION_SECRET) {
      const payload = verifyCookieValue(SESSION_SECRET, cv);
      if (payload && payload.sid) {
        const sess = sessionStore.get(payload.sid);
        if (sess && sess.user) {
          req.user = sess.user;
          req._authSid = payload.sid;
        }
      }
    }
  } catch (_) {}
  next();
});

async function loadProviderPreset(providerId) {
  const presetPath = path.join(__dirname, "oidc_providers", `${providerId}.json`);
  try {
    const raw = await fsp.readFile(presetPath, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function getOidcRuntimeConfig() {
  const preset = await loadProviderPreset(OIDC_PROVIDER);
  if (!preset) throw new Error("oidc_provider_preset_missing");
  const issuer = OIDC_ISSUER || "";
  if (!issuer) {
    // issuer must be explicitly provided (we don't guess tenant/realm)
    throw new Error("oidc_issuer_required");
  }
  const cfg = await OIDC.discover(issuer);
  return { preset, issuer, cfg };
}


// ==========================
// 기본 설정
// ==========================

// ==========================
// ✅ 슈퍼급 기본 보안 헤더 (의존성 없이)
// - SECURE_HEADERS=1 (default) 이면 적용
// - HTTPS 모드에서는 HSTS도 자동 적용
// ==========================
const SECURE_HEADERS = String(process.env.SECURE_HEADERS || "1").trim() !== "0";
const HSTS_MAX_AGE = process.env.HSTS_MAX_AGE ? parseInt(process.env.HSTS_MAX_AGE, 10) : 15552000; // 180d

if (SECURE_HEADERS) {
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");

    // ✅ CSP: dashboard가 inline script를 쓰기 때문에 'unsafe-inline' 유지(최소 수정)
    // (추후 nonce 기반으로 더 강화 가능)
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    );

    // HTTPS일 때 HSTS
    const isHttps = req.secure || (req.headers["x-forwarded-proto"] === "https");
    if (isHttps && HSTS_MAX_AGE > 0) {
      res.setHeader("Strict-Transport-Security", `max-age=${HSTS_MAX_AGE}; includeSubDomains`);
    }

    next();
  });
}


// ==========================
//  (추가만) Express trust proxy 정책 고정
// - 기존 로직 절대 변경 안 함
// - TRUST_PROXY=1 일 때만 활성화
// - TRUSTED_PROXY_CIDRS가 있으면 해당 CIDR만 신뢰 (XFF spoof 방지 강화)
// - 없으면 true (ngrok/Cloudflare 포함 프록시 뒤 운영 전제)
// ==========================
const __TP = String(process.env.TRUST_PROXY || "0").trim().toLowerCase();
const __TPCIDRS_RAW = String(process.env.TRUSTED_PROXY_CIDRS || "").trim();
if (__TP === "1" || __TP === "true") {
  if (__TPCIDRS_RAW) {
    const __list = __TPCIDRS_RAW
      .split(",")
      .map(s => s.trim())
      .filter(Boolean);
    app.set("trust proxy", __list);
  } else {
    app.set("trust proxy", true);
  }
} else {
  app.set("trust proxy", false);
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: process.env.JSON_LIMIT || "128kb" }));

// ==========================
// ✅ JSON parse error handler (standardized)
// ==========================
app.use((err, req, res, next) => {
  if (err && (err.type === "entity.parse.failed" || err instanceof SyntaxError)) {
    return sendError(res, 400, "invalid_json", "Invalid JSON body.", req);
  }
  return next(err);
});




// ==========================
// mTLS gate (optional)
// - When MTLS_REQUIRE=1, the relay will only accept requests from clients with an allowed client-cert fingerprint.
// ==========================
function mtlsGate(req, res, next) {
    // allow browser/OIDC routes without mTLS (agents still require mTLS on /api/*)
    if (req.path === "/login" || req.path === "/oidc/callback" || req.path === "/" || req.path === "/dashboard") return next();
 
  try {
    if (!MTLS_REQUIRE) return next();
    // Only meaningful on HTTPS server with requestCert enabled
    const cert = req.socket && typeof req.socket.getPeerCertificate === 'function' ? req.socket.getPeerCertificate() : null;
    const fp = cert && (cert.fingerprint256 || cert.fingerprint) ? String(cert.fingerprint256 || cert.fingerprint).replace(/:/g,'').toLowerCase() : '';
    if (!fp) return sendError(res, 401, 'unauthorized', 'mTLS client certificate required.', req);
    if (MTLS_CLIENT_FINGERPRINTS.length && !MTLS_CLIENT_FINGERPRINTS.includes(fp)) {
      return sendError(res, 403, 'forbidden', 'mTLS client certificate not allowlisted.', req);
    }
    req._mtlsFp = fp;
    return next();
  } catch {
    return sendError(res, 401, 'unauthorized', 'mTLS client certificate required.', req);
  }
}
app.use(mtlsGate);
// Health check
app.get("/healthz", (req, res) => res.json({ ok: true, ts: Date.now(), mode: MODE, auditRemoteDegraded: AUDIT_REMOTE_DEGRADED }));


// ==========================
// ✅ Same-Origin 보호 (CSRF 방어용, 최소 수정)
// - 브라우저 요청(Origin/Referer 존재)일 때만 강제
// - Dashboard fetch는 X-Requested-With: GenieSecurityDashboard 헤더를 항상 포함해야 함
// - curl/agent(Origin/Referer 없음)는 영향 없음
// ==========================
function requireSameOrigin(req, res, next) {
  try {
    const origin = req.headers["origin"];
    const referer = req.headers["referer"];
    // Non-browser clients usually omit Origin/Referer
    if (!origin && !referer) return next();

    const host = req.headers["host"];
    const allowHttp = `http://${host}`;
    const allowHttps = `https://${host}`;

    let ok = false;
    if (origin) ok = (origin === allowHttp || origin === allowHttps);
    if (!ok && referer) ok = (referer.startsWith(allowHttp + "/") || referer.startsWith(allowHttps + "/"));

    if (!ok) return res.status(403).json({ ok: false, error: "csrf_blocked" });

    const xrw = String(req.headers["x-requested-with"] || "");
    if (xrw !== "GenieSecurityDashboard") {
      return res.status(403).json({ ok: false, error: "missing_xrw" });
    }
    return next();
  } catch (e) {
    return res.status(403).json({ ok: false, error: "csrf_blocked" });
  }
}


// ==========================
// ENV
// ==========================
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;

const REGISTRY_PATH = process.env.REGISTRY_PATH || path.join(DATA_DIR, "registry.json");
const SESSIONS_PATH = process.env.SESSIONS_PATH || path.join(DATA_DIR, "sessions.json");

// ==========================
// ✅ Sessions purge (product-grade)
// - Prevent sessions.json from growing without bound in long-running deployments.
// - Purges EXPIRED/FAIL old entries periodically; enforces a soft max size.
// ==========================
const SESSIONS_PURGE_INTERVAL_SEC = parseInt(process.env.SESSIONS_PURGE_INTERVAL_SEC || "60", 10); // 0 disables
const SESSIONS_MAX = parseInt(process.env.SESSIONS_MAX || "5000", 10);
const SESSIONS_PURGE_EXPIRED_GRACE_SEC = parseInt(process.env.SESSIONS_PURGE_EXPIRED_GRACE_SEC || "300", 10);
const SESSIONS_PURGE_FAIL_GRACE_SEC = parseInt(process.env.SESSIONS_PURGE_FAIL_GRACE_SEC || "86400", 10);

const AUDIT_LOG_PATH = process.env.AUDIT_LOG_PATH || path.join(DATA_DIR, "audit.jsonl");

const STRUCTURED_LOG_PATH = process.env.STRUCTURED_LOG_PATH || path.join(ROOT_DIR, "relay", "logs", "relay_structured.jsonl");
const POLICY_DIR = process.env.POLICY_DIR || path.join(ROOT_DIR, "relay", "policy");
// ✅ Policy path (fix: ReferenceError "POLICY_PATH is not defined" in /api/diagnostics/self-check)
// - Prefer explicit env POLICY_PATH; relative paths are resolved from the current module dir.
// - Fallback: <policy_dir>/policy.json
const POLICY_PATH = (() => {
  const p = String(process.env.POLICY_PATH || "").trim();
  if (p) return path.isAbsolute(p) ? p : path.join(__dirname, p);
  return path.join(POLICY_DIR, "policy.json");
})();
const DEVICE_ALLOWLIST_PATH = process.env.DEVICE_ALLOWLIST_PATH || path.join(POLICY_DIR, "device_allowlist.json");
const ENFORCE_DEVICE_ALLOWLIST = String(process.env.ENFORCE_DEVICE_ALLOWLIST || "0") === "1";

// Audit signing (optional)
const AUDIT_SIGNING_KEY_ID = process.env.AUDIT_SIGNING_KEY_ID || "k1";
const AUDIT_SIGNING_PRIV_B64 = process.env.AUDIT_SIGNING_PRIV_B64 || _readSecretFileMaybe(process.env.AUDIT_SIGNING_PRIV_FILE || ""); // ed25519 pkcs8 der base64
const AUDIT_SIGNING_PUB_B64 = process.env.AUDIT_SIGNING_PUB_B64 || _readSecretFileMaybe(process.env.AUDIT_SIGNING_PUB_FILE || "");   // ed25519 spki der base64

// Enforce audit signing when required (secure deployments should turn this on)
const AUDIT_REQUIRE_SIGNING = /^(1|true|yes)$/i.test(String(process.env.AUDIT_REQUIRE_SIGNING || ""));
if (AUDIT_REQUIRE_SIGNING && !AUDIT_SIGNING_PRIV_B64) {
  console.error("[FATAL] AUDIT_REQUIRE_SIGNING=1 but AUDIT_SIGNING_PRIV_B64 is missing. Refusing to start.");
  process.exit(2);
}

const AUDIT_REMOTE_URL = process.env.AUDIT_REMOTE_URL || ""; // https://... best-effort POST
const AUDIT_REMOTE_HMAC_B64 = process.env.AUDIT_REMOTE_HMAC_B64 || ""; // base64 key for HMAC-SHA256
const AUDIT_REMOTE_TIMEOUT_MS = process.env.AUDIT_REMOTE_TIMEOUT_MS
  ? parseInt(process.env.AUDIT_REMOTE_TIMEOUT_MS, 10)
  : 1500;

const AUDIT_REMOTE_REQUIRED = /^(1|true|yes)$/i.test(String(process.env.AUDIT_REMOTE_REQUIRED || ""));
const AUDIT_REMOTE_SPOOL_PATH = process.env.AUDIT_REMOTE_SPOOL_PATH || path.join(DATA_DIR, 'audit_remote_spool.jsonl');
let AUDIT_REMOTE_DEGRADED = false;

// Secrets can be provided via *_B64 env OR *_FILE (recommended for ops hardening)
function _readSecretFileMaybe(pth){
  try{
    if (!pth) return "";
    const abs = path.isAbsolute(pth) ? pth : path.join(ROOT_DIR, pth);
    if (!fs.existsSync(abs)) return "";
    const v = fs.readFileSync(abs, 'utf8').trim();
    return v;
  } catch(_) { return ""; }
}

const MASTER_KEY_B64 = process.env.MASTER_KEY_B64 || _readSecretFileMaybe(process.env.MASTER_KEY_FILE || "");

const OPERATOR_ID = process.env.OPERATOR_ID || "operator";
const OPERATOR_KEY = process.env.OPERATOR_KEY || "";
const OPERATOR2_ID = process.env.OPERATOR2_ID || "operator2";
const OPERATOR2_KEY = process.env.OPERATOR2_KEY || "";
const TWO_MAN_RULE = String(process.env.TWO_MAN_RULE || "0").trim() === "1";

// ==========================
// SECURE MODE ENFORCEMENT (product-grade defaults)
// - In MODE=secure, we fail fast on dangerous configuration drift.
// ==========================
function _fatal(msg){ console.error('[FATAL] ' + msg); process.exit(2); }

if (MODE === 'secure') {
  if (!AUDIT_REQUIRE_SIGNING) _fatal('MODE=secure requires AUDIT_REQUIRE_SIGNING=1 (audit tamper-evidence).');
  if (!AUDIT_REMOTE_URL) _fatal('MODE=secure requires AUDIT_REMOTE_URL (remote/WORM audit export).');
  if (!AUDIT_REMOTE_HMAC_B64) _fatal('MODE=secure requires AUDIT_REMOTE_HMAC_B64 (integrity for remote audit ingest).');
  if (!DISABLE_LEGACY_OPERATOR_KEY) _fatal('MODE=secure requires DISABLE_LEGACY_OPERATOR_KEY=1 (disable legacy operatorKey auth).');
  if (!OIDC_ENABLED) _fatal('MODE=secure requires OIDC_ENABLED=1 (strong operator identity).');
  if (!REQUIRE_OIDC) _fatal('MODE=secure requires REQUIRE_OIDC=1 (OIDC mandatory).');
  if (!REQUIRE_TOTP) _fatal('MODE=secure requires REQUIRE_TOTP=1 (step-up/OTP required).');
  if (!TWO_MAN_RULE) _fatal('MODE=secure requires TWO_MAN_RULE=1 (two-man approval).');
}

//  TRUST_PROXY: reverse proxy/Nginx/Cloudflare 뒤에서 XFF를 쓰기 위한 토글
const TRUST_PROXY = String(process.env.TRUST_PROXY || "0").trim();

//  Trusted Proxy CIDR (XFF를 신뢰할 프록시/로드밸런서 IP 대역)
const TRUSTED_PROXY_CIDRS_RAW = String(process.env.TRUSTED_PROXY_CIDRS || "").trim();

//  Spoof 차단 옵션: 의심스러운 XFF / Private IP / invalid IP 를 강제 차단
const SPOOF_BLOCK = String(process.env.SPOOF_BLOCK || "false").trim().toLowerCase();
const REQUIRE_VALID_CLIENT_IP = String(process.env.REQUIRE_VALID_CLIENT_IP || "true").trim().toLowerCase();

//  (추가) 내부망 기본형 옵션: private IPv4 허용 여부
// - 내부망/로컬 PoC: true
// - 외부 Secure형: false
const ALLOW_PRIVATE_IP_CLIENT = String(process.env.ALLOW_PRIVATE_IP_CLIENT || "false").trim().toLowerCase();

//  TRUST_PROXY_MODE (옵션) : cloudflare / nginx / generic
const TRUST_PROXY_MODE = String(process.env.TRUST_PROXY_MODE || "generic").trim().toLowerCase();
const TRUST_PROXY_ALLOW_ANY_REMOTE = String(process.env.TRUST_PROXY_ALLOW_ANY_REMOTE || "false").trim().toLowerCase();


// ✅ 포트 범위
const PORT_MIN = process.env.PORT_MIN ? parseInt(process.env.PORT_MIN, 10) : 40000;
const PORT_MAX = process.env.PORT_MAX ? parseInt(process.env.PORT_MAX, 10) : 45000;

// ✅ 기본 OPEN TTL (sec) - 운영자 승인 흐름(기본)
const DEFAULT_OPEN_TTL_SEC = process.env.DEFAULT_OPEN_TTL_SEC
  ? parseInt(process.env.DEFAULT_OPEN_TTL_SEC, 10)
  : 180;

// ✅ 세션 만료 60초 전 알림 UX를 위한 warn threshold
const EXPIRING_SOON_SEC = process.env.EXPIRING_SOON_SEC
  ? parseInt(process.env.EXPIRING_SOON_SEC, 10)
  : 60;

// ✅ Extend 설정 (v1 현실적 UX)
const EXTEND_SEC = process.env.EXTEND_SEC ? parseInt(process.env.EXTEND_SEC, 10) : 180; // 기본 3분
const EXTEND_MAX_COUNT = process.env.EXTEND_MAX_COUNT
  ? parseInt(process.env.EXTEND_MAX_COUNT, 10)
  : 1; // 기본 1회 제한


// ✅ (Policy) max concurrent OPENED sessions per server (default 1)
const MAX_OPENED_PER_SERVER = process.env.MAX_OPENED_PER_SERVER
  ? Math.max(1, parseInt(process.env.MAX_OPENED_PER_SERVER, 10))
  : 1;
// ✅ (Policy) when enforced-close queued but no close report arrives, auto-mark as done after this timeout
const ENFORCED_CLOSE_TIMEOUT_SEC = process.env.ENFORCED_CLOSE_TIMEOUT_SEC
  ? Math.max(30, parseInt(process.env.ENFORCED_CLOSE_TIMEOUT_SEC, 10))
  : 120;
function parseBool(v, def = false) {
  if (v === undefined || v === null) return def;
  const t = String(v).trim().toLowerCase();
  return t === "1" || t === "true" || t === "yes" || t === "on";
}
const EXTEND_ALLOW_ONLY_WHITELIST = parseBool(process.env.EXTEND_ALLOW_ONLY_WHITELIST, false);

// ✅ expire tick interval
const EXPIRE_TICK_MS = process.env.EXPIRE_TICK_MS ? parseInt(process.env.EXPIRE_TICK_MS, 10) : 5000;

// ==========================
// ✅ (A) 정책 기반 부분 자동승인 (Whitelist 조합만)
// ==========================
const AUTO_APPROVE_TTL_SEC = process.env.AUTO_APPROVE_TTL_SEC
  ? parseInt(process.env.AUTO_APPROVE_TTL_SEC, 10)
  : 180; //  기본 3분 (짧게)

const AUTO_APPROVE_WHITELIST_RAW = process.env.AUTO_APPROVE_WHITELIST || "";

function parseWhitelistPairs(raw) {
  const set = new Set();
  const t = String(raw || "").trim();
  if (!t) return set;
  const parts = t.split(",");
  for (const p of parts) {
    const s = String(p || "").trim();
    if (!s) continue;
    const idx = s.indexOf(":");
    if (idx <= 0) continue;
    const clientUuid = s.slice(0, idx).trim();
    const serverUuid = s.slice(idx + 1).trim();
    if (!clientUuid || !serverUuid) continue;
    set.add(`${clientUuid}::${serverUuid}`);
  }
  return set;
}
let AUTO_APPROVE_SET = parseWhitelistPairs(AUTO_APPROVE_WHITELIST_RAW);

function isAutoApprovePair(clientUuid, serverUuid) {
  if (!clientUuid || !serverUuid) return false;
  return AUTO_APPROVE_SET.has(`${clientUuid}::${serverUuid}`);
}

// ==========================
// ✅ (NEW) [프롬프트6] Whitelist 기반 “부분 자동 승인” (clientUuid + serverUuid + ip)
// - 기존 AUTO_APPROVE_PAIR 로직은 유지 (하위 호환)
// - 새로운 Triple Whitelist는 "추가 강화" 옵션
// - env 기반(추가만): AUTO_APPROVE_TRIPLE_WHITELIST
//   format:
//     1) clientUuid:serverUuid:ip
//     2) clientUuid:serverUuid:ipCidr(/24)
//   examples:
//     c-111:s-222:203.0.113.10
//     c-777:s-888:203.0.113.0/24
// ==========================
const AUTO_APPROVE_TRIPLE_WHITELIST_RAW = process.env.AUTO_APPROVE_TRIPLE_WHITELIST || "";

function normalizeIpForMatch(ip) {
  if (!ip) return "";
  let s = String(ip).trim();
  if (s.startsWith("::ffff:")) s = s.replace("::ffff:", "");
  if (s === "::1") s = "127.0.0.1";
  return s;
}

function ipv4ToInt(ip) {
  const p = ip.split(".").map(x => parseInt(x, 10));
  return ((p[0] << 24) >>> 0) + ((p[1] << 16) >>> 0) + ((p[2] << 8) >>> 0) + (p[3] >>> 0);
}

function parseCidr4One(cidrStr) {
  try {
    const s = String(cidrStr || "").trim();
    if (!s) return null;
    const [ipStr, prefixStr] = s.split("/");
    const ip = normalizeIpForMatch(ipStr);
    const prefix = parseInt(prefixStr, 10);
    if (net.isIP(ip) !== 4) return null;
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) return null;
    const baseInt = ipv4ToInt(ip);
    const maskInt = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1) >>> 0);
    return { cidr: `${ip}/${prefix}`, baseInt, maskInt, prefix };
  } catch (_) {
    return null;
  }
}

function ip4InCidr(ip, cidrObj) {
  try {
    const x = normalizeIpForMatch(ip);
    if (net.isIP(x) !== 4) return false;
    const xi = ipv4ToInt(x);
    return (((xi & cidrObj.maskInt) >>> 0) === ((cidrObj.baseInt & cidrObj.maskInt) >>> 0));
  } catch (_) {
    return false;
  }
}

// triple rules = array of { id, clientUuid, serverUuid, ipExact?, ipCidrObj?, enabled, note }
function parseTripleWhitelist(raw) {
  const rules = [];
  const t = String(raw || "").trim();
  if (!t) return rules;

  const parts = t.split(",").map(x => String(x || "").trim()).filter(Boolean);
  let idx = 0;

  for (const part of parts) {
    // clientUuid:serverUuid:ipOrCidr
    const segs = part.split(":").map(x => String(x || "").trim());
    if (segs.length < 3) continue;
    const clientUuid = segs[0];
    const serverUuid = segs[1];
    const ipOrCidr = segs.slice(2).join(":"); // just in case
    if (!clientUuid || !serverUuid || !ipOrCidr) continue;

    const id = `wl_env_${String(++idx).padStart(4, "0")}`;

    if (ipOrCidr.includes("/")) {
      const cidrObj = parseCidr4One(ipOrCidr);
      if (!cidrObj) continue;
      rules.push({
        id,
        clientUuid,
        serverUuid,
        ipCidr: cidrObj.cidr,
        ipCidrObj: cidrObj,
        enabled: true,
        note: "env_triple_whitelist_cidr",
      });
    } else {
      const ipExact = normalizeIpForMatch(ipOrCidr);
      if (net.isIP(ipExact) === 0) continue;
      rules.push({
        id,
        clientUuid,
        serverUuid,
        ipExact,
        enabled: true,
        note: "env_triple_whitelist_exact",
      });
    }
  }

  return rules;
}

let AUTO_APPROVE_TRIPLE_RULES = parseTripleWhitelist(AUTO_APPROVE_TRIPLE_WHITELIST_RAW);

function matchAutoApproveTriple(clientUuid, serverUuid, clientIp) {
  const ip = normalizeIpForMatch(clientIp);
  for (const r of AUTO_APPROVE_TRIPLE_RULES) {
    if (!r || r.enabled === false) continue;
    if (r.clientUuid !== clientUuid) continue;
    if (r.serverUuid !== serverUuid) continue;

    if (r.ipExact) {
      if (normalizeIpForMatch(r.ipExact) === ip) {
        return {
          ok: true,
          ruleId: r.id,
          policy: "WHITELIST_TRIPLE_EXACT",
          reason: "clientUuid+serverUuid+ip exact matched",
        };
      }
    } else if (r.ipCidrObj) {
      if (ip4InCidr(ip, r.ipCidrObj)) {
        return {
          ok: true,
          ruleId: r.id,
          policy: "WHITELIST_TRIPLE_CIDR",
          reason: "clientUuid+serverUuid+ip cidr matched",
        };
      }
    }
  }
  return { ok: false };
}

// ==========================
// ✅ (NEW) Rate Limit / Abuse 방지 (최상위 보안)
// - IP 기준 + clientUuid 기준
// - 최소 수정: 메모리 기반(프로세스 재시작 시 리셋)
// ==========================
const RATE_LIMIT_WINDOW_SEC = process.env.RATE_LIMIT_WINDOW_SEC
  ? parseInt(process.env.RATE_LIMIT_WINDOW_SEC, 10)
  : 60; // 60초 윈도우

const RATE_LIMIT_IP_PER_WINDOW = process.env.RATE_LIMIT_IP_PER_WINDOW
  ? parseInt(process.env.RATE_LIMIT_IP_PER_WINDOW, 10)
  : 10; // IP당 10req/60s

const RATE_LIMIT_CLIENT_PER_WINDOW = process.env.RATE_LIMIT_CLIENT_PER_WINDOW
  ? parseInt(process.env.RATE_LIMIT_CLIENT_PER_WINDOW, 10)
  : 20; // clientUuid당 20req/60s

const rlIp = {};      // { key: { count, resetAt } }
const rlClient = {};  // { key: { count, resetAt } }

function rateLimitHit(map, key, limit, now) {
  if (!key) return { ok: true };
  const o = map[key];
  if (!o || typeof o.resetAt !== "number" || o.resetAt <= now) {
    map[key] = { count: 1, resetAt: now + RATE_LIMIT_WINDOW_SEC };
    return { ok: true, remaining: limit - 1, resetAt: map[key].resetAt };
  }
  o.count = (typeof o.count === "number" ? o.count : 0) + 1;
  if (o.count > limit) {
    return { ok: false, remaining: 0, resetAt: o.resetAt, count: o.count };
  }
  return { ok: true, remaining: Math.max(0, limit - o.count), resetAt: o.resetAt };
}

async function enforceRateLimitOrThrow(clientIp, clientUuid) {
  const t = nowSec();

  const ipKey = String(clientIp || "").trim();
  const clKey = String(clientUuid || "").trim();

  const r1 = rateLimitHit(rlIp, ipKey, RATE_LIMIT_IP_PER_WINDOW, t);
  if (!r1.ok) {
    await appendAudit("RATE_LIMIT_BLOCKED", {
      scope: "ip",
      key: ipKey,
      limit: RATE_LIMIT_IP_PER_WINDOW,
      windowSec: RATE_LIMIT_WINDOW_SEC,
      count: r1.count,
      resetAt: r1.resetAt,
    });
    const err = new Error("rate_limited_ip");
    err.code = "rate_limited_ip";
    err.meta = { resetAt: r1.resetAt, windowSec: RATE_LIMIT_WINDOW_SEC, limit: RATE_LIMIT_IP_PER_WINDOW };
    throw err;
  }

  const r2 = rateLimitHit(rlClient, clKey, RATE_LIMIT_CLIENT_PER_WINDOW, t);
  if (!r2.ok) {
    await appendAudit("RATE_LIMIT_BLOCKED", {
      scope: "clientUuid",
      key: clKey,
      limit: RATE_LIMIT_CLIENT_PER_WINDOW,
      windowSec: RATE_LIMIT_WINDOW_SEC,
      count: r2.count,
      resetAt: r2.resetAt,
    });
    const err = new Error("rate_limited_client");
    err.code = "rate_limited_client";
    err.meta = { resetAt: r2.resetAt, windowSec: RATE_LIMIT_WINDOW_SEC, limit: RATE_LIMIT_CLIENT_PER_WINDOW };
    throw err;
  }

  return { ok: true };
}

// ==========================
// 유틸
// ==========================

function getRealIp(req) {
  // Trust proxy setting already handled by Express when enabled; use req.ip
  // Keep simple; the policy engine treats unknown as not-private.
  return (req && (req.ip || (req.connection && req.connection.remoteAddress))) ? String(req.ip || req.connection.remoteAddress) : "";
}
function nowSec() {
  return Math.floor(Date.now() / 1000);
}

// ==========================
// Input validation helpers (ASVS-aligned, minimal)
// ==========================
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function isUuid(v) {
  return typeof v === "string" && UUID_RE.test(v.trim());
}
function needUuid(v, field) {
  if (!isUuid(v)) {
    const e = new Error(`Invalid ${field}`);
    e.status = 400;
    e.code = "INVALID_INPUT";
    throw e;
  }
  return v.trim();
}
function needStr(v, field, maxLen = 256) {
  if (typeof v !== "string") {
    const e = new Error(`Invalid ${field}`);
    e.status = 400;
    e.code = "INVALID_INPUT";
    throw e;
  }
  const s = v.trim();
  if (!s || s.length > maxLen) {
    const e = new Error(`Invalid ${field}`);
    e.status = 400;
    e.code = "INVALID_INPUT";
    throw e;
  }
  return s;
}

function safeJsonParse(s, fallback = null) {
  try {
    return JSON.parse(s);
  } catch (e) {
    return fallback;
  }
}

async function ensureDataDir() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
}

function b64ToBuf(b64) {
  return Buffer.from(b64, "base64");
}

function bufToB64(buf) {
  return buf.toString("base64");
}

// ==========================
// AES-256-GCM (MASTER_KEY_B64)
// ==========================
function requireMasterKey() {
  if (!MASTER_KEY_B64) throw new Error("MASTER_KEY_B64 missing");
  const key = b64ToBuf(MASTER_KEY_B64);
  if (key.length !== 32) throw new Error("MASTER_KEY_B64 must be 32 bytes base64");
  return key;
}

function aesGcmEncryptJson(obj) {
  const key = requireMasterKey();
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    iv: bufToB64(iv),
    tag: bufToB64(tag),
    data: bufToB64(ciphertext),
  };
}

function aesGcmDecryptJson(enc) {
  const key = requireMasterKey();
  if (!enc || enc.v !== 1) throw new Error("bad enc format");
  const iv = b64ToBuf(enc.iv);
  const tag = b64ToBuf(enc.tag);
  const data = b64ToBuf(enc.data);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

// ==========================
// ✅ (NEW) OpenToken v1 (AES-256-GCM, MASTER_KEY_B64)
// format: v1.<iv_b64>.<tag_b64>.<data_b64>
// payload: { sid, serverUuid, clientIp, assignedPort, iat, exp, jti }
// ==========================
const OPEN_TOKEN_VERSION = "v1";

// jti replay 방지 캐시(메모리). { jti: expSec }
const jtiUsed = {};
// ✅ [P13~P14] usedJti 영구 저장 + purge 정책 (파일 크기 폭증 방지)
const USED_JTI_PATH = path.join(DATA_DIR, "used_jti.json");
const USED_JTI_VERSION = 1;
const USED_JTI_MAX_ITEMS = parseInt(process.env.USED_JTI_MAX_ITEMS || "200000", 10);
let usedJtiSaveTimer = null;

function loadUsedJtiFromFile() {
  try {
    if (!fs.existsSync(USED_JTI_PATH)) return;
    const raw = fs.readFileSync(USED_JTI_PATH, "utf-8");
    const obj = JSON.parse(raw);
    if (!obj || obj.version !== USED_JTI_VERSION || typeof obj.items !== "object") return;
    for (const [jti, expSec] of Object.entries(obj.items)) {
      if (typeof expSec === "number") jtiUsed[jti] = expSec;
    }
    console.log(` [USED_JTI] loaded: ${Object.keys(jtiUsed).length}`);
  } catch (e) {
    console.log(" [USED_JTI] load failed:", e.message);
  }
}

function scheduleSaveUsedJti() {
  if (usedJtiSaveTimer) return;
  usedJtiSaveTimer = setTimeout(() => {
    usedJtiSaveTimer = null;
    saveUsedJtiToFile();
  }, 500);
}

function saveUsedJtiToFile() {
  try {
    const payload = { version: USED_JTI_VERSION, savedAt: nowSec(), items: jtiUsed };
    fs.writeFileSync(USED_JTI_PATH, JSON.stringify(payload, null, 2), "utf-8");
  } catch (e) {
    console.log(" [USED_JTI] save failed:", e.message);
  }
}

function purgeUsedJti() {
  try {
    const t = nowSec();
    for (const [jti, expSec] of Object.entries(jtiUsed)) {
      if (typeof expSec !== "number" || expSec <= t) delete jtiUsed[jti];
    }
    const keys = Object.keys(jtiUsed);
    if (keys.length > USED_JTI_MAX_ITEMS) {
      keys.sort((a, b) => (jtiUsed[a] || 0) - (jtiUsed[b] || 0));
      const removeCount = keys.length - USED_JTI_MAX_ITEMS;
      for (let i = 0; i < removeCount; i++) delete jtiUsed[keys[i]];
    }
    scheduleSaveUsedJti();
  } catch (_) {}
}

// ✅ load persisted usedJti
loadUsedJtiFromFile(); //  load persisted usedJti


function cleanupJtiUsed(now) {
  try {
    for (const jti of Object.keys(jtiUsed)) {
      const exp = jtiUsed[jti];
      if (!exp || exp <= now) delete jtiUsed[jti];
    }
  } catch (_) {}
}

function openTokenEncryptPayload(payload) {
  const key = requireMasterKey();
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${OPEN_TOKEN_VERSION}.${bufToB64(iv)}.${bufToB64(tag)}.${bufToB64(ciphertext)}`;
}

function issueOpenTokenForSession(s) {
  const t = nowSec();

  // 이미 발급된 토큰이 있으면 그대로 재사용(같은 세션에서 중복 발급 방지)
  if (s && s.openToken && typeof s.openToken === "string") {
    return s.openToken;
  }

  const exp = (s && typeof s.expiresAt === "number") ? s.expiresAt : (t + DEFAULT_OPEN_TTL_SEC);
  const jti = crypto.randomBytes(16).toString("hex");

  const payload = {
    sid: s.sessionId,
    serverUuid: s.serverUuid,
    clientIp: s.clientIp,
    assignedPort: s.assignedPort,
    iat: t,
    exp,
    jti,
  };

  // ✅ replay 방지 캐시에 등록
  jtiUsed[jti] = exp;

  const token = openTokenEncryptPayload(payload);

  // ✅ 세션에 토큰 저장(재발급 금지)
  s.openToken = token;
  s.openTokenIssuedAt = t;
  s.openTokenJti = jti;

  return token;
}

// ==========================
// Audit (async safe)
// ==========================
let AUDIT_LAST_HASH = process.env.AUDIT_GENESIS_HASH || "GENESIS";

async function initAuditHashChain() {
  try {
    if (!fs.existsSync(AUDIT_LOG_PATH)) return;
    const raw = await fsp.readFile(AUDIT_LOG_PATH, "utf8");
    const lines = raw.split("\n").filter(Boolean);
    if (lines.length === 0) return;
    const last = safeJsonParse(lines[lines.length - 1], null);
    if (last && last.hash) {
      AUDIT_LAST_HASH = String(last.hash);
      return;
    }
  } catch (e) {
    // ignore
  }
}


async function sendAuditRemote(entry) {
  try {
    if (!AUDIT_REMOTE_URL) return true;
    const u = new URL(AUDIT_REMOTE_URL);
    const isHttps = u.protocol === "https:";
    const mod = isHttps ? require("https") : require("http");
    const body = Buffer.from(JSON.stringify(entry), "utf8");
    const headers = {
      "Content-Type": "application/json",
      "Content-Length": String(body.length),
    };
    if (AUDIT_REMOTE_HMAC_B64) {
      const key = Buffer.from(AUDIT_REMOTE_HMAC_B64, "base64");
      const mac = crypto.createHmac("sha256", key).update(body).digest("base64");
      headers["X-GenieSecurity-Audit-HMAC"] = mac;
    }
    const opts = {
      method: "POST",
      hostname: u.hostname,
      port: u.port ? parseInt(u.port, 10) : (isHttps ? 443 : 80),
      path: u.pathname + (u.search || ""),
      headers,
      timeout: AUDIT_REMOTE_TIMEOUT_MS,
    };
    const ok = await new Promise((resolve) => {
      const req = mod.request(opts, (res) => {
        res.on("data", () => {});
        res.on("end", () => resolve(res.statusCode >= 200 && res.statusCode < 300));
      });
      req.on("timeout", () => { try { req.destroy(); } catch (_) {} resolve(false); });
      req.on("error", () => resolve(false));
      req.write(body);
      req.end();
    });
    return ok;
  } catch (e) {
    return false;
  }
}

// 슈퍼급: Audit 변조 방지(해시체인)
// entry.hash = sha256( prevHash + "|" + JSON(entry_without_hash) )
async function appendAudit(eventType, details = {}) {
  try {
    await ensureDataDir();
    await initAuditHashChain();
    const base = {
      ts: nowSec(),
      iso: new Date().toISOString(),
      event: eventType,
      details,
      prevHash: AUDIT_LAST_HASH,
    };
    const baseJson = JSON.stringify(base);
    const hash = crypto.createHash("sha256").update(String(AUDIT_LAST_HASH) + "|" + baseJson, "utf8").digest("hex");
    let sig = null;
    let keyId = null;
    try {
      if (AUDIT_SIGNING_PRIV_B64) {
        const priv = crypto.createPrivateKey({ key: Buffer.from(AUDIT_SIGNING_PRIV_B64, "base64"), format: "der", type: "pkcs8" });
        const msg = Buffer.from(hash, "utf8");
        const sigBuf = crypto.sign(null, msg, priv);
        sig = sigBuf.toString("base64");
        keyId = AUDIT_SIGNING_KEY_ID;
      }
    } catch (e) {
      // ignore signing errors
    }
    const entry = { ...base, hash, ...(sig ? { sig, keyId } : {}) };
    const line = JSON.stringify(entry) + "\n";
    await fsp.appendFile(AUDIT_LOG_PATH, line, "utf8");
    AUDIT_LAST_HASH = hash;

    // ✅ SIEM export (best-effort, non-blocking)
    try { SIEM.enqueue(toEcsEvent(entry)); } catch (_) {}

    // ✅ Remote audit export (best-effort; can be REQUIRED in MODE=secure)
    try {
      const ok = await sendAuditRemote(entry);
      if (!ok) {
        if (AUDIT_REMOTE_REQUIRED || MODE === 'secure') {
          AUDIT_REMOTE_DEGRADED = true;
          try { await fsp.appendFile(AUDIT_REMOTE_SPOOL_PATH, JSON.stringify(entry) + '\n', 'utf8'); } catch(_) {}
        }
      }
    } catch(_) {}
  } catch (e) {
    console.error(" [AUDIT] append 실패:", e.message);
  }
}


let DEVICE_ALLOWLIST_CACHE = null;
let DEVICE_ALLOWLIST_MTIME = 0;

async function loadDeviceAllowlist() {
  try {
    await fsp.mkdir(POLICY_DIR, { recursive: true });
    if (!fs.existsSync(DEVICE_ALLOWLIST_PATH)) {
      // default allow all (empty lists)
      const def = { updatedAt: new Date().toISOString(), clients: {}, servers: {} };
      await fsp.writeFile(DEVICE_ALLOWLIST_PATH, JSON.stringify(def, null, 2), "utf8");
    }
    const st = await fsp.stat(DEVICE_ALLOWLIST_PATH);
    if (DEVICE_ALLOWLIST_CACHE && st.mtimeMs === DEVICE_ALLOWLIST_MTIME) return DEVICE_ALLOWLIST_CACHE;
    const raw = await fsp.readFile(DEVICE_ALLOWLIST_PATH, "utf8");
    DEVICE_ALLOWLIST_CACHE = safeJsonParse(raw, { clients: {}, servers: {} }) || { clients: {}, servers: {} };
    DEVICE_ALLOWLIST_MTIME = st.mtimeMs;
    return DEVICE_ALLOWLIST_CACHE;
  } catch (e) {
    return { clients: {}, servers: {} };
  }
}

async function enforceDeviceAllowlist(kind, uuid, fp, info, res, context = {}) {
  if (!ENFORCE_DEVICE_ALLOWLIST) return true;
  const allow = await loadDeviceAllowlist();
  const table = kind === "server" ? (allow.servers || {}) : (allow.clients || {});
  const allowedFps = table[String(uuid || "")] || [];
  const ok = allowedFps.includes(String(fp || ""));
  if (!ok) {
    await appendAudit("DEVICE_BLOCKED", {
      kind, uuid, fp, info,
      reason: "device_not_allowlisted",
      ...context
    });
    res.status(403).json({ ok: false, error: "DEVICE_NOT_ALLOWED" });
    return false;
  }
  return true;
}
// ✅ (추가) Audit 조회 유틸
async function readAuditLines(limit = 200) {
  try {
    if (!fs.existsSync(AUDIT_LOG_PATH)) return [];
    const raw = await fsp.readFile(AUDIT_LOG_PATH, "utf8");
    const lines = raw.split("\n").filter(Boolean);
    const sliced = lines.slice(Math.max(0, lines.length - limit));
    const parsed = [];
    for (const line of sliced) {
      const obj = safeJsonParse(line, null);
      if (obj) parsed.push(obj);
    }
    return parsed;
  } catch (e) {
    return [];
  }
}

// ==========================
// 메모리 저장소
// ==========================
const servers = {};   // { serverUuid: { serverUuid, serverPsk, ... } }
const clients = {};   // { clientUuid: { clientUuid, clientPsk, ... } }
const sessions = {};  // { sid_xxx: { status, expiresAt, ... } }
const commands = {};  // { serverUuid: [ {type, ...} ] }

/**
 * ==========================
 * ✅ PoP (Proof-of-Possession) for clientPsk (P0-1)
 * - HMAC-SHA256(clientPsk, canonical)
 * - Replay protection via nonce cache (in-memory)
 * - Always-Closed: deny before session creation
 * ==========================
 */
const POP_TS_SKEW_SEC = parseInt(process.env.POP_TS_SKEW_SEC || "60", 10);
const POP_NONCE_TTL_SEC = parseInt(process.env.POP_NONCE_TTL_SEC || "180", 10);
const POP_FAIL_WINDOW_SEC = parseInt(process.env.POP_FAIL_WINDOW_SEC || "300", 10);
const POP_FAIL_MAX = parseInt(process.env.POP_FAIL_MAX || "20", 10);
const POP_BLOCK_SEC = parseInt(process.env.POP_BLOCK_SEC || "600", 10);

const popNonceCache = new Map();   // key -> expiresAtMs
const popFailCounter = new Map();  // key(ip|clientUuid) -> { count, resetAtMs }
const popBlockUntil = new Map();   // key(ip|clientUuid) -> untilMs

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function _randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function _b64url(buf) {
  return buf.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function _popCanonical(method, apiPath, clientUuid, serverUuid, ts, nonce) {
  return [
    "GS-POP-V1",
    (method || "").toUpperCase(),
    apiPath,
    `clientUuid=${clientUuid}`,
    `serverUuid=${serverUuid}`,
    `ts=${ts}`,
    `nonce=${nonce}`,
  ].join("\n");
}

function _purgePopNonceCache(nowMs) {
  // lightweight purge
  if (popNonceCache.size === 0) return;
  for (const [k, exp] of popNonceCache.entries()) {
    if (exp <= nowMs) popNonceCache.delete(k);
  }
}

function _failKey(ip, clientUuid) {
  return `${ip || "unknown"}|${clientUuid || "-"}`;
}

function _nonceKey(clientUuid, serverUuid, nonce) {
  return `${clientUuid}|${serverUuid}|${nonce}`;
}

async function denyWithDelay(req, res, ipInfo, reason, meta) {
  // Scan resistance: random delay 800~1500ms
  await _sleep(_randInt(800, 1500));
  try {
    await appendAudit("POP_DENIED", {
      reason: reason || "denied",
      meta: meta || {},
      clientUuid: (req.body || {}).clientUuid,
      serverUuid: (req.body || {}).serverUuid,
      ip: (ipInfo && ipInfo.clientIp) || extractRemoteAddress(req),
    });
  } catch (_) {}
  return res.status(403).json({ ok: false, error: "denied" });
}

async function verifyClientPoPOrDeny(req, res, ipInfo) {
  const ip = (ipInfo && ipInfo.clientIp) || extractRemoteAddress(req) || "unknown";
  const body = req.body || {};
  const { clientUuid, serverUuid, ts, nonce, pop } = body;

  const fk = _failKey(ip, clientUuid);
  const nowMs = Date.now();

  // temp block
  const until = popBlockUntil.get(fk);
  if (until && until > nowMs) {
    return denyWithDelay(req, res, ipInfo, "blocked", { untilMs: until });
  } else if (until && until <= nowMs) {
    popBlockUntil.delete(fk);
  }

  // required fields
  if (!clientUuid || !serverUuid || !ts || !nonce || !pop) {
    // count fail
    const rec = popFailCounter.get(fk) || { count: 0, resetAtMs: nowMs + POP_FAIL_WINDOW_SEC * 1000 };
    if (rec.resetAtMs <= nowMs) {
      rec.count = 0;
      rec.resetAtMs = nowMs + POP_FAIL_WINDOW_SEC * 1000;
    }
    rec.count += 1;
    popFailCounter.set(fk, rec);
    if (rec.count >= POP_FAIL_MAX) popBlockUntil.set(fk, nowMs + POP_BLOCK_SEC * 1000);
    return denyWithDelay(req, res, ipInfo, "missing_fields", { count: rec.count });
  }

  const client = clients[clientUuid];
  if (!client || !client.clientPsk) {
    const rec = popFailCounter.get(fk) || { count: 0, resetAtMs: nowMs + POP_FAIL_WINDOW_SEC * 1000 };
    if (rec.resetAtMs <= nowMs) {
      rec.count = 0;
      rec.resetAtMs = nowMs + POP_FAIL_WINDOW_SEC * 1000;
    }
    rec.count += 1;
    popFailCounter.set(fk, rec);
    if (rec.count >= POP_FAIL_MAX) popBlockUntil.set(fk, nowMs + POP_BLOCK_SEC * 1000);
    return denyWithDelay(req, res, ipInfo, "client_not_registered", { count: rec.count });
  }

  const tsNum = parseInt(ts, 10);
  if (!Number.isFinite(tsNum)) {
    const rec = popFailCounter.get(fk) || { count: 0, resetAtMs: nowMs + POP_FAIL_WINDOW_SEC * 1000 };
    if (rec.resetAtMs <= nowMs) {
      rec.count = 0;
      rec.resetAtMs = nowMs + POP_FAIL_WINDOW_SEC * 1000;
    }
    rec.count += 1;
    popFailCounter.set(fk, rec);
    if (rec.count >= POP_FAIL_MAX) popBlockUntil.set(fk, nowMs + POP_BLOCK_SEC * 1000);
    return denyWithDelay(req, res, ipInfo, "bad_ts", { count: rec.count });
  }

  const nowSec = Math.floor(nowMs / 1000);
  if (Math.abs(nowSec - tsNum) > POP_TS_SKEW_SEC) {
    const rec = popFailCounter.get(fk) || { count: 0, resetAtMs: nowMs + POP_FAIL_WINDOW_SEC * 1000 };
    if (rec.resetAtMs <= nowMs) {
      rec.count = 0;
      rec.resetAtMs = nowMs + POP_FAIL_WINDOW_SEC * 1000;
    }
    rec.count += 1;
    popFailCounter.set(fk, rec);
    if (rec.count >= POP_FAIL_MAX) popBlockUntil.set(fk, nowMs + POP_BLOCK_SEC * 1000);
    return denyWithDelay(req, res, ipInfo, "ts_out_of_range", { count: rec.count, nowSec, ts: tsNum });
  }

  _purgePopNonceCache(nowMs);
  const nk = _nonceKey(clientUuid, serverUuid, nonce);
  if (popNonceCache.has(nk)) {
    const rec = popFailCounter.get(fk) || { count: 0, resetAtMs: nowMs + POP_FAIL_WINDOW_SEC * 1000 };
    if (rec.resetAtMs <= nowMs) {
      rec.count = 0;
      rec.resetAtMs = nowMs + POP_FAIL_WINDOW_SEC * 1000;
    }
    rec.count += 1;
    popFailCounter.set(fk, rec);
    if (rec.count >= POP_FAIL_MAX) popBlockUntil.set(fk, nowMs + POP_BLOCK_SEC * 1000);
    return denyWithDelay(req, res, ipInfo, "replay", { count: rec.count });
  }
  popNonceCache.set(nk, nowMs + POP_NONCE_TTL_SEC * 1000);

  // compute expected pop
  const canonical = _popCanonical("POST", "/api/client/request-access", clientUuid, serverUuid, tsNum, nonce);
  const expected = _b64url(require("crypto").createHmac("sha256", Buffer.from(String(client.clientPsk), "utf8")).update(canonical, "utf8").digest());

  // timing-safe compare
  try {
    const a = Buffer.from(String(expected), "utf8");
    const b = Buffer.from(String(pop), "utf8");
    if (a.length !== b.length) throw new Error("len_mismatch");
    if (!require("crypto").timingSafeEqual(a, b)) throw new Error("mismatch");
  } catch (e) {
    const rec = popFailCounter.get(fk) || { count: 0, resetAtMs: nowMs + POP_FAIL_WINDOW_SEC * 1000 };
    if (rec.resetAtMs <= nowMs) {
      rec.count = 0;
      rec.resetAtMs = nowMs + POP_FAIL_WINDOW_SEC * 1000;
    }
    rec.count += 1;
    popFailCounter.set(fk, rec);
    if (rec.count >= POP_FAIL_MAX) popBlockUntil.set(fk, nowMs + POP_BLOCK_SEC * 1000);
    return denyWithDelay(req, res, ipInfo, "bad_pop", { count: rec.count });
  }

  // success: clear fail counter (soft)
  popFailCounter.delete(fk);
  popBlockUntil.delete(fk);
  return true;
}


/**
 * ==========================
 * ✅ Idempotency (operator write APIs)
 * - Prevent duplicate state transitions caused by retries / double-clicks / races.
 * - Stores per-session per-action result keyed by Idempotency-Key.
 * - Persisted inside sessions.json (as s._idem[action][key] = {ts, statusCode, body})
 * ==========================
 */
function getIdemKey(req) {
  const k = String(req.get("Idempotency-Key") || "").trim();
  return k.length >= 8 ? k : null;
}
function idemReplay(res, record) {
  res.status(record.statusCode || 200).json(record.body || { ok:false, error:"idem_replay_no_body" });
}
function idemStore(s, action, key, statusCode, body) {
  if (!s) return;
  if (!s._idem) s._idem = {};
  if (!s._idem[action]) s._idem[action] = {};
  // store minimal info
  s._idem[action][key] = { ts: Date.now(), statusCode, body };
}
function idemLookup(s, action, key) {
  if (!s || !s._idem || !s._idem[action]) return null;
  return s._idem[action][key] || null;
}

// ==========================
// ✅ Pending consume (in-memory only)
// - confirm-open 에서 KEM 패키지 발급 후, consume-open 에서 PoP 검증되면 실제 consumed 처리
// - 공격자가 confirm-open을 가져가도 서버 priv 없이는 consume 불가 => 1회 소비 DoS 방지
// ==========================
const pendingConsumes = {}; // { jti: { serverUuid, sessionId, kid, ephPrivRawB64, saltB64, challengeB64, macB64, expSec, createdAt } }

function purgePendingConsumes() {
  const t = nowSec();
  for (const [jti, rec] of Object.entries(pendingConsumes)) {
    if (!rec) { delete pendingConsumes[jti]; continue; }
    const exp = typeof rec.expSec === "number" ? rec.expSec : (t - 1);
    // exp 또는 createdAt+120 중 빠른 쪽
    const ttlExp = (typeof rec.createdAt === "number" ? rec.createdAt + 120 : t - 1);
    if (exp <= t || ttlExp <= t) delete pendingConsumes[jti];
  }
}
setInterval(purgePendingConsumes, 5000).unref();


// ==========================
// 저장/로드 (encrypted json)
// ==========================
async function saveEncryptedJson(filePath, obj) {
  await ensureDataDir();
  await initAuditHashChain();
  const enc = aesGcmEncryptJson(obj);
  const tmpPath = filePath + ".tmp";
  await fsp.writeFile(tmpPath, JSON.stringify(enc, null, 2), "utf8");
  await fsp.rename(tmpPath, filePath);
}

async function loadEncryptedJson(filePath) {
  if (!fs.existsSync(filePath)) return null;
  const raw = await fsp.readFile(filePath, "utf8");
  const enc = safeJsonParse(raw, null);
  if (!enc) return null;
  return aesGcmDecryptJson(enc);
}

async function loadRegistry() {
  try {
    const obj = await loadEncryptedJson(REGISTRY_PATH);
    if (!obj) return { ok: false, source: "none" };
    if (obj.servers) Object.assign(servers, obj.servers);
    if (obj.clients) Object.assign(clients, obj.clients);
    await appendAudit("REGISTRY_LOADED", { servers: Object.keys(servers).length, clients: Object.keys(clients).length });
    console.log(" [REGISTRY] loaded:", Object.keys(servers).length, "servers,", Object.keys(clients).length, "clients");
    return { ok: true, source: "file" };
  } catch (e) {
    console.error(" [REGISTRY] load failed:", e.message);
    await appendAudit("REGISTRY_LOAD_FAILED", { error: e.message });
    return { ok: false, source: "error" };
  }
}

// ==========================
// ✅ P0-1 Bootstrap seeding (product-safe default: OFF)
//
// Why:
// - In USB/offline demos, registry.json may not exist on first boot.
// - P0-1 PoP is Always-Closed and requires a registered clientPsk.
// - Without a registry seed, request-access returns POP_DENIED(client_not_registered) → 403 denied.
//
// How:
// - If SEED_CLIENTS=1, seed clients from env and persist using encrypted registry.json.
// - Format:
//   SEED_CLIENTS=1
//   SEED_CLIENT_ENTRIES=clientUuidA:clientPskDummy,clientUuidB:pskB
//
// Notes:
// - This is intended for demo/test only. Keep SEED_CLIENTS=0 in production.
// - Requires MASTER_KEY_B64 to be set (registry is encrypted).
// ==========================
function parseSeedEntries(raw) {
  const s = String(raw || "").trim();
  if (!s) return [];
  return s
    .split(",")
    .map(x => x.trim())
    .filter(Boolean)
    .map(pair => {
      const idx = pair.indexOf(":");
      if (idx <= 0) return null;
      const id = pair.slice(0, idx).trim();
      const psk = pair.slice(idx + 1).trim();
      if (!id || !psk) return null;
      return { id, psk };
    })
    .filter(Boolean);
}

async function seedClientsIfEnabled() {
  const enabled = String(process.env.SEED_CLIENTS || "0").trim() === "1";
  if (!enabled) return { ok: false, reason: "disabled" };

  const entries = parseSeedEntries(process.env.SEED_CLIENT_ENTRIES || "");
  if (!entries.length) return { ok: false, reason: "no_entries" };

  let added = 0;
  for (const it of entries) {
    if (!clients[it.id]) {
      clients[it.id] = {
        clientUuid: it.id,
        clientPsk: it.psk,
        createdAt: nowSec(),
      };
      added += 1;
    }
  }

  if (added > 0) {
    await saveRegistry();
    await appendAudit("CLIENTS_SEEDED", { added, total: Object.keys(clients).length });
    console.log(` [REGISTRY] clients seeded: +${added} (total=${Object.keys(clients).length})`);
  } else {
    await appendAudit("CLIENTS_SEED_SKIPPED", { reason: "already_present", total: Object.keys(clients).length });
  }

  return { ok: true, added };
}

async function maybeSeedClientsOnBoot() {
  try {
    const enabled = String(process.env.SEED_CLIENTS || "0").trim() === "1";
    if (!enabled) return;

    const entries = parseSeedEntries(process.env.SEED_CLIENT_ENTRIES || "");
    if (!entries.length) {
      console.log(" [SEED_CLIENTS] enabled but SEED_CLIENT_ENTRIES empty. Skipping.");
      return;
    }

    let added = 0;
    for (const it of entries) {
      if (clients[it.id] && clients[it.id].clientPsk) continue;
      clients[it.id] = {
        ...(clients[it.id] || {}),
        clientUuid: it.id,
        clientPsk: it.psk,
        createdAt: (clients[it.id] && clients[it.id].createdAt) ? clients[it.id].createdAt : nowSec(),
        seededAt: nowSec(),
      };
      added += 1;
    }

    if (added > 0) {
      await saveRegistry();
      await appendAudit("CLIENT_SEEDED", { count: added, ids: entries.map(e => e.id) });
      console.log(` [SEED_CLIENTS] seeded ${added} client(s) into registry.json`);
    } else {
      console.log(" [SEED_CLIENTS] no new clients to seed.");
    }
  } catch (e) {
    console.log(" [SEED_CLIENTS] failed:", e.message);
  }
}

async function saveRegistry() {
  try {
    const obj = { servers, clients };
    await saveEncryptedJson(REGISTRY_PATH, obj);
    await appendAudit("REGISTRY_SAVED", { servers: Object.keys(servers).length, clients: Object.keys(clients).length });
    return { ok: true };
  } catch (e) {
    console.error(" [REGISTRY] save failed:", e.message);
    await appendAudit("REGISTRY_SAVE_FAILED", { error: e.message });
    return { ok: false, error: e.message };
  }
}

async function loadSessions() {
  try {
    const obj = await loadEncryptedJson(SESSIONS_PATH);
    if (!obj) return { ok: false, source: "none" };
    if (obj.sessions) Object.assign(sessions, obj.sessions);
    if (obj.jtiUsed && typeof obj.jtiUsed === "object") Object.assign(jtiUsed, obj.jtiUsed);
    await appendAudit("SESSIONS_LOADED", { sessions: Object.keys(sessions).length });
    console.log(" [SESSIONS] loaded:", Object.keys(sessions).length);
    return { ok: true, source: "file" };
  } catch (e) {
    console.error(" [SESSIONS] load failed:", e.message);
    await appendAudit("SESSIONS_LOAD_FAILED", { error: e.message });
    return { ok: false, source: "error" };
  }
}

async function saveSessions() {
  try {
    const obj = { sessions, jtiUsed };
    await saveEncryptedJson(SESSIONS_PATH, obj);
    await appendAudit("SESSIONS_SAVED", { sessions: Object.keys(sessions).length });
    return { ok: true };
  } catch (e) {
    console.error(" [SESSIONS] save failed:", e.message);
    await appendAudit("SESSIONS_SAVE_FAILED", { error: e.message });
    return { ok: false, error: e.message };
  }
}


function reconcileSessionsOnBoot() {
  const t = nowSec();
  let changed = 0;
  // expire sessions whose expiresAt passed
  for (const sid of Object.keys(sessions)) {
    const s = sessions[sid];
    if (!s || typeof s !== "object") continue;
    if (typeof s.expiresAt === "number" && s.expiresAt <= t) {
      if (s.status === "OPENED" || s.status === "PENDING") {
        s.status = "EXPIRED";
        s.expiredAt = t;
        changed++;
      }
    }
  }
  // cleanup jtiUsed map
  cleanupJtiUsed(t);
  return { changed };
}
// ==========================
// ✅ Sessions purge engine
// ==========================
let LAST_PURGE = null; // { ts, removedExpired, removedFail, removedOverMax, before, after, reason }

function _sessionSortKey(s) {
  // older first
  const a = (typeof s.createdAt === "number" ? s.createdAt : 0);
  const b = (typeof s.expiresAt === "number" ? s.expiresAt : 0);
  const c = (typeof s.updatedAt === "number" ? s.updatedAt : 0);
  return a || b || c || 0;
}

async function purgeSessions(reason = "interval") {
  try {
    if (!SESSIONS_PURGE_INTERVAL_SEC || SESSIONS_PURGE_INTERVAL_SEC <= 0) return { ok: true, disabled: true };

    const t = nowSec();
    const before = Object.keys(sessions).length;
    let removedExpired = 0;
    let removedFail = 0;
    let removedOverMax = 0;

    // 1) Purge old EXPIRED
    for (const sid of Object.keys(sessions)) {
      const s = sessions[sid];
      if (!s || typeof s !== "object") { delete sessions[sid]; removedExpired++; continue; }
      if (s.status === "EXPIRED") {
        const exp = (typeof s.expiresAt === "number" ? s.expiresAt : (typeof s.expiredAt === "number" ? s.expiredAt : 0));
        if (exp && exp <= (t - SESSIONS_PURGE_EXPIRED_GRACE_SEC)) {
          delete sessions[sid];
          removedExpired++;
        }
      }
    }

    // 2) Purge old FAIL
    for (const sid of Object.keys(sessions)) {
      const s = sessions[sid];
      if (!s || typeof s !== "object") continue;
      if (s.status === "FAIL") {
        const k = _sessionSortKey(s) || t;
        if (k <= (t - SESSIONS_PURGE_FAIL_GRACE_SEC)) {
          delete sessions[sid];
          removedFail++;
        }
      }
    }

    // 3) Enforce max size (soft): remove oldest EXPIRED -> FAIL -> PENDING
    const keysNow = Object.keys(sessions);
    let over = keysNow.length - SESSIONS_MAX;
    if (over > 0) {
      const bucket = { EXPIRED: [], FAIL: [], PENDING: [] };
      for (const sid of keysNow) {
        const s = sessions[sid];
        if (!s || typeof s !== "object") continue;
        if (s.status === "EXPIRED") bucket.EXPIRED.push([sid, _sessionSortKey(s)]);
        else if (s.status === "FAIL") bucket.FAIL.push([sid, _sessionSortKey(s)]);
        else if (s.status === "PENDING") bucket.PENDING.push([sid, _sessionSortKey(s)]);
      }
      for (const k of ["EXPIRED", "FAIL", "PENDING"]) {
        bucket[k].sort((a,b) => (a[1]||0) - (b[1]||0));
        for (const [sid] of bucket[k]) {
          if (over <= 0) break;
          delete sessions[sid];
          removedOverMax++;
          over--;
        }
        if (over <= 0) break;
      }
    }

    const after = Object.keys(sessions).length;
    const removedTotal = removedExpired + removedFail + removedOverMax;

    LAST_PURGE = { ts: t, removedExpired, removedFail, removedOverMax, before, after, reason };

    if (removedTotal > 0) {
      await appendAudit("SESSIONS_PURGED", LAST_PURGE);
      await saveSessions();
    }

    return { ok: true, ...LAST_PURGE, removedTotal };
  } catch (e) {
    LAST_PURGE = { ts: nowSec(), error: e.message, reason };
    await appendAudit("SESSIONS_PURGE_FAILED", { error: e.message, reason });
    return { ok: false, error: e.message };
  }
}

// ==========================
// ✅ Trusted Proxy CIDR 파서 + IP 검사
// ==========================
function normalizeIp(ip) {
  if (!ip) return "";
  let s = String(ip).trim();
  if (s.startsWith("::ffff:")) s = s.replace("::ffff:", "");
  if (s === "::1") s = "127.0.0.1";
  return s;
}

function isValidIp(ip) {
  const s = normalizeIp(ip);
  return net.isIP(s) !== 0;
}

function isPrivateIpv4(ip) {
  const s = normalizeIp(ip);
  if (net.isIP(s) !== 4) return false;
  const parts = s.split(".").map(x => parseInt(x, 10));
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

// CIDR → { baseInt, maskInt }
function parseCidrList(raw) {
  const list = [];
  const t = String(raw || "").trim();
  if (!t) return list;
  const parts = t.split(",");
  for (const part of parts) {
    const s = String(part || "").trim();
    if (!s) continue;
    const [ipStr, prefixStr] = s.split("/");
    const ip = normalizeIp(ipStr);
    const prefix = parseInt(prefixStr, 10);
    if (net.isIP(ip) !== 4) continue;
    if (!Number.isFinite(prefix) || prefix < 0 || prefix > 32) continue;
    const baseInt = ipv4ToInt(ip);
    const maskInt = prefix === 0 ? 0 : (~((1 << (32 - prefix)) - 1) >>> 0);
    list.push({ cidr: `${ip}/${prefix}`, baseInt, maskInt });
  }
  return list;
}

const TRUSTED_PROXY_CIDRS = parseCidrList(TRUSTED_PROXY_CIDRS_RAW);

function isTrustedProxyRemote(remoteIp) {
  const allowAny = (TRUST_PROXY_ALLOW_ANY_REMOTE === "1" || TRUST_PROXY_ALLOW_ANY_REMOTE === "true");
  if (allowAny && TRUSTED_PROXY_CIDRS.length === 0) return true;

  const ip = normalizeIp(remoteIp);
  if (net.isIP(ip) !== 4) return false; // v1에서는 IPv4 CIDR만 지원
  const x = ipv4ToInt(ip);
  for (const c of TRUSTED_PROXY_CIDRS) {
    if (((x & c.maskInt) >>> 0) === ((c.baseInt & c.maskInt) >>> 0)) return true;
  }
  return false;
}

function extractRemoteAddress(req) {
  // Node의 실제 소켓 remoteAddress (proxy 무관)
  const ra = req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : "";
  return normalizeIp(ra);
}

function getHeader(req, name) {
  const v = req.headers[name.toLowerCase()];
  if (!v) return "";
  if (Array.isArray(v)) return v[0] || "";
  return String(v);
}

// Cloudflare: CF-Connecting-IP / True-Client-IP / X-Forwarded-For
function extractClientIpViaProxy(req) {
  if (TRUST_PROXY_MODE === "cloudflare") {
    const cf = normalizeIp(getHeader(req, "cf-connecting-ip"));
    if (cf) return cf;
    const tc = normalizeIp(getHeader(req, "true-client-ip"));
    if (tc) return tc;
  }
  // generic / nginx fallback: X-Forwarded-For 첫번째
  const xff = getHeader(req, "x-forwarded-for");
  if (xff) {
    const first = normalizeIp(xff.split(",")[0].trim());
    if (first) return first;
  }
  // 최종 fallback
  const rip = normalizeIp(req.ip || "");
  if (rip) return rip;
  return "";
}

/**
 * ✅ 특허 핵심에 맞는 client IP 확정 로직
 */
function resolveClientIpOrThrow(req) {
  const remoteAddr = extractRemoteAddress(req);
  const hasXff = !!getHeader(req, "x-forwarded-for");
  const hasCf = !!getHeader(req, "cf-connecting-ip") || !!getHeader(req, "true-client-ip");

  const trustProxyEnabled = (TRUST_PROXY === "1" || TRUST_PROXY === "true");

  // 기본 clientIp = remoteAddr
  let clientIp = remoteAddr;
  let usedProxyHeader = false;
  let trustedProxy = false;

  if (trustProxyEnabled) {
    trustedProxy = isTrustedProxyRemote(remoteAddr);
    if (trustedProxy) {
      const via = extractClientIpViaProxy(req);
      if (via) {
        clientIp = normalizeIp(via);
        usedProxyHeader = true;
      }
    } else {
      const spoofBlock = (SPOOF_BLOCK === "1" || SPOOF_BLOCK === "true");
      if (spoofBlock && (hasXff || hasCf)) {
        const err = new Error("spoof_suspected_untrusted_proxy");
        err.code = "spoof_suspected_untrusted_proxy";
        err.meta = { remoteAddr, hasXff, hasCf };
        throw err;
      }
    }
  }

  const requireValid = (REQUIRE_VALID_CLIENT_IP === "1" || REQUIRE_VALID_CLIENT_IP === "true");
  if (requireValid) {
    if (!isValidIp(clientIp)) {
      const err = new Error("invalid_client_ip");
      err.code = "invalid_client_ip";
      err.meta = { clientIp, remoteAddr, usedProxyHeader, trustedProxy };
      throw err;
    }

    const allowPrivate = (ALLOW_PRIVATE_IP_CLIENT === "1" || ALLOW_PRIVATE_IP_CLIENT === "true");
    if (!allowPrivate) {
      if (isPrivateIpv4(clientIp)) {
        const err = new Error("private_client_ip_denied");
        err.code = "private_client_ip_denied";
        err.meta = { clientIp, remoteAddr, usedProxyHeader, trustedProxy, allowPrivate };
        throw err;
      }
    }
  }

  return {
    clientIp,
    remoteAddr,
    usedProxyHeader,
    trustedProxy,
  };
}

// ==========================
// startup
// ==========================
(async () => {
  await ensureDataDir();
  await initAuditHashChain();
  await loadRegistry();
  await maybeSeedClientsOnBoot();
  await loadSessions();
  const rc = reconcileSessionsOnBoot();
  if (rc.changed > 0) await saveSessions();

  // ✅ sessions purge scheduler (product-grade)
  if (SESSIONS_PURGE_INTERVAL_SEC > 0) {
    await purgeSessions("boot");
    setInterval(() => {
      purgeSessions("interval").catch(() => {});
    }, SESSIONS_PURGE_INTERVAL_SEC * 1000).unref?.();
    console.log(" [SESSIONS_PURGE] intervalSec =", SESSIONS_PURGE_INTERVAL_SEC, "max =", SESSIONS_MAX);
  } else {
    console.log(" [SESSIONS_PURGE] disabled");
  }


  console.log(" [AUTO_APPROVE] TTL_SEC =", AUTO_APPROVE_TTL_SEC);
  console.log(" [AUTO_APPROVE] pairs =", AUTO_APPROVE_SET.size);

  console.log(" [AUTO_APPROVE_TRIPLE] rules =", AUTO_APPROVE_TRIPLE_RULES.length);

  console.log(" [PROXY] TRUST_PROXY =", TRUST_PROXY);
  console.log(" [PROXY] MODE =", TRUST_PROXY_MODE);
  console.log(" [PROXY] SPOOF_BLOCK =", SPOOF_BLOCK);
  console.log(" [PROXY] REQUIRE_VALID_CLIENT_IP =", REQUIRE_VALID_CLIENT_IP);
  console.log(" [PROXY] ALLOW_PRIVATE_IP_CLIENT =", ALLOW_PRIVATE_IP_CLIENT);
  console.log(" [PROXY] TRUSTED_PROXY_CIDRS =", TRUSTED_PROXY_CIDRS.map(x => x.cidr).join(",") || "(none)");

  console.log(" [RATE_LIMIT] WINDOW_SEC =", RATE_LIMIT_WINDOW_SEC);
  console.log(" [RATE_LIMIT] IP_PER_WINDOW =", RATE_LIMIT_IP_PER_WINDOW);
  console.log(" [RATE_LIMIT] CLIENT_PER_WINDOW =", RATE_LIMIT_CLIENT_PER_WINDOW);

  await appendAudit("AUTO_APPROVE_CONFIG", {
    ttlSec: AUTO_APPROVE_TTL_SEC,
    pairsCount: AUTO_APPROVE_SET.size,
    enabled: AUTO_APPROVE_SET.size > 0
  });

  await appendAudit("AUTO_APPROVE_TRIPLE_CONFIG", {
    rulesCount: AUTO_APPROVE_TRIPLE_RULES.length,
    enabled: AUTO_APPROVE_TRIPLE_RULES.length > 0
  });

  await appendAudit("PROXY_CONFIG", {
    trustProxy: TRUST_PROXY,
    mode: TRUST_PROXY_MODE,
    spoofBlock: SPOOF_BLOCK,
    requireValidClientIp: REQUIRE_VALID_CLIENT_IP,
    allowPrivateIpClient: ALLOW_PRIVATE_IP_CLIENT,
    trustedCidrs: TRUSTED_PROXY_CIDRS.map(x => x.cidr),
  });

  await appendAudit("RATE_LIMIT_CONFIG", {
    windowSec: RATE_LIMIT_WINDOW_SEC,
    ipPerWindow: RATE_LIMIT_IP_PER_WINDOW,
    clientPerWindow: RATE_LIMIT_CLIENT_PER_WINDOW,
  });
})();

// ==========================
// port allocator
// ==========================
function randomPort() {
  // ✅ crypto-grade RNG (슈퍼급): Math.random() 금지
  // crypto.randomInt(min, max) where max is exclusive
  return crypto.randomInt(PORT_MIN, PORT_MAX + 1);
}

function isPortInUse(p) {
  for (const sid of Object.keys(sessions)) {
    const s = sessions[sid];
    if (!s) continue;
    if (s.status !== "OPENED") continue;
    if (s.assignedPort === p) return true;
  }
  return false;
}

function allocatePort() {
  for (let i = 0; i < 200; i++) {
    const p = randomPort();
    if (!isPortInUse(p)) return p;
  }
  for (let p = PORT_MIN; p <= PORT_MAX; p++) {
    if (!isPortInUse(p)) return p;
  }
  throw new Error("no available port");
}

// ==========================
// session id
// ==========================
function newSessionId() {
  return "sid_" + crypto.randomBytes(12).toString("hex");
}

// ==========================
// commands queue
// ==========================
function enqueueCommand(serverUuid, cmd) {
  if (!commands[serverUuid]) commands[serverUuid] = [];
  commands[serverUuid].push({ ...cmd, enqueuedAt: nowSec() });
}

// ==========================
// ✅ 강제 회수 로직(핵심): 만료 시 CLOSE_FIREWALL enqueue
// ==========================
function enqueueCloseFirewallForSession(sid, s, reason) {
  try {
    if (!s || !s.serverUuid) return;
    const serverUuid = s.serverUuid;
    enqueueCommand(serverUuid, {
      type: "CLOSE_FIREWALL",
      sessionId: sid,
      assignedPort: s.assignedPort,
      remoteIp: s.clientIp,
      reason: reason || "expired",
    });
  } catch (_) {}
}

// ✅ (NEW) Fail-Block 강제 회수 유틸
async function forceCloseEnforced(sid, s, reason, meta = {}) {
  const t = nowSec();

  if (!s) return { ok: false, error: "session_not_found" };

  if (s.status !== "EXPIRED" && s.status !== "REJECTED") {
    s.status = "EXPIRED";
    s.expiredAt = t;
  }

  if (typeof s.closeEnforcedAt !== "number") {
    enqueueCloseFirewallForSession(sid, s, reason || "fail_block");
    s.closeEnforcedAt = t;
  }

  await saveSessions();

  await appendAudit("FAIL_BLOCK_ENFORCED", {
    sessionId: sid,
    serverUuid: s.serverUuid,
    clientUuid: s.clientUuid,
    assignedPort: s.assignedPort,
    clientIp: s.clientIp,
    reason: reason || "fail_block",
    meta,
    closeEnforcedAt: s.closeEnforcedAt,
    status: s.status,
  });

  return { ok: true };
}

// ==========================
// ✅ 만료 세션 tick
// ==========================
async function expireSessionsTick() {
  try {
    const t = nowSec();
    cleanupJtiUsed(t);
    let changed = false;

    for (const sid of Object.keys(sessions)) {
      const s = sessions[sid];
      if (!s) continue;

      if (s.status === "EXPIRED" || s.status === "REJECTED") continue;

      if (s.status === "OPENED" && typeof s.expiresAt === "number") {
        const remain = s.expiresAt - t;
        if (remain > 0 && remain <= EXPIRING_SOON_SEC && typeof s.warnedAt !== "number") {
          s.warnedAt = t;
          changed = true;

          await appendAudit("SESSION_EXPIRING_SOON", {
            sessionId: sid,
            serverUuid: s.serverUuid,
            clientUuid: s.clientUuid,
            assignedPort: s.assignedPort,
            expiresAt: s.expiresAt,
            remainSec: remain,
          });
        }
      }

      if (typeof s.expiresAt === "number" && s.expiresAt <= t) {
        s.status = "EXPIRED";
        s.expiredAt = t;
        changed = true;

        await appendAudit("SESSION_EXPIRED", {
          sessionId: sid,
          serverUuid: s.serverUuid,
          clientUuid: s.clientUuid,
          assignedPort: s.assignedPort,
          expiresAt: s.expiresAt,
        });

        if (typeof s.closeEnforcedAt !== "number") {
          enqueueCloseFirewallForSession(sid, s, "expired");
          s.closeEnforcedAt = t;
          changed = true;

          await appendAudit("CLOSE_ENFORCED_ENQUEUED", {
            sessionId: sid,
            serverUuid: s.serverUuid,
            assignedPort: s.assignedPort,
            clientIp: s.clientIp,
            reason: "expired",
          });
        }
      }
    }

    if (changed) {
      await saveSessions();
    }
  } catch (e) {
    console.error(" [SESSIONS] expire tick 실패:", e.message);
  }
}

setInterval(async () => {
  await expireSessionsTick();
}, EXPIRE_TICK_MS);

// ==========================
// operator auth
// ==========================
function operatorAuth(req, res, next) {
  // NOTE(product/offline): Some operator endpoints are GET and may not carry a JSON body.
  // Accept operator credentials from (1) headers, (2) query, (3) JSON body.
  // This also enables safe CLI diagnostics via curl.
  const h = req.headers || {};
  const q = req.query || {};
  const b = req.body || {};
  const operatorId = (h["x-operator-id"] || h["operator-id"] || q.operatorId || q.operator_id || b.operatorId || b.operator_id || "").toString();
  const operatorKey = (h["x-operator-key"] || h["operator-key"] || q.operatorKey || q.operator_key || b.operatorKey || b.operator_key || "").toString();
  const ok1 = operatorId === OPERATOR_ID && operatorKey === OPERATOR_KEY;
  const ok2 = operatorId === OPERATOR2_ID && operatorKey === OPERATOR2_KEY;

  // TWO_MAN_RULE=1 이면 operator2 키가 반드시 설정되어야 함
  if (TWO_MAN_RULE && (!OPERATOR2_KEY || OPERATOR2_KEY.length < 16)) {
    return res.status(500).json({ ok: false, error: "operator2_not_configured" });
  }

  if (!ok1 && !ok2) {
    return res.status(403).json({ ok: false, error: "operator_auth_failed" });
  }

  // 누구로 인증됐는지 downstream에 전달
  req._operatorId = operatorId;
  req._operatorRole = ok1 ? "OP1" : "OP2";
  next();
}

// ==========================
// health
// ==========================
app.get("/health", (req, res) => {
  res.json({ ok: true, ts: nowSec() });
});

// ==========================

// ==========================
// OIDC Routes
// - /login -> redirects to IdP
// - /oidc/callback -> exchanges code, verifies id_token, creates session
// - /logout -> clears session cookie
// ==========================
app.get("/api/me", (req, res) => {
  if (req.user) return res.json({ ok: true, authenticated: true, user: req.user });
  return res.json({ ok: true, authenticated: false });
});

app.get("/login", async (req, res) => {
  try {
    if (!OIDC_ENABLED) return res.status(404).send("OIDC disabled");
    if (!SESSION_SECRET || SESSION_SECRET.length < 32) return res.status(500).send("SESSION_SECRET not configured");
    if (!OIDC_CLIENT_ID || !OIDC_REDIRECT_URI) return res.status(500).send("OIDC client not configured");

    const { preset, issuer, cfg } = await getOidcRuntimeConfig();

    const state = _randomId(18);
    const nonce = OIDC.randomB64Url(18);
    const pkceVerifier = OIDC.randomB64Url(48);
    const pkceChallenge = OIDC.pkceChallengeS256(pkceVerifier);
    oidcPutState(state, nonce, pkceVerifier);

    const url = OIDC.buildAuthUrl({
      authorization_endpoint: cfg.authorization_endpoint,
      client_id: OIDC_CLIENT_ID,
      redirect_uri: OIDC_REDIRECT_URI,
      scope: OIDC_SCOPE,
      state,
      nonce,
      prompt: req.query.prompt ? String(req.query.prompt) : undefined,
      code_challenge: pkceChallenge,
      code_challenge_method: "S256",
    });

    res.redirect(url);
  } catch (e) {
    console.error("[OIDC] /login error:", e);
    res.status(500).send("OIDC login failed");
  }
});

app.get("/oidc/callback", async (req, res) => {
  try {
    if (!OIDC_ENABLED) return res.status(404).send("OIDC disabled");
    if (!SESSION_SECRET || SESSION_SECRET.length < 32) return res.status(500).send("SESSION_SECRET not configured");

    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code || !state) return res.status(400).send("missing code/state");

    const st = oidcPopState(state);
    if (!st) return res.status(400).send("invalid_state");

    const { preset, issuer, cfg } = await getOidcRuntimeConfig();
    const tok = await OIDC.exchangeCode({
      token_endpoint: cfg.token_endpoint,
      client_id: OIDC_CLIENT_ID,
      client_secret: OIDC_CLIENT_SECRET,
      redirect_uri: OIDC_REDIRECT_URI,
      code_verifier: st.pkceVerifier,
      code,
    });

    if (!tok || !tok.id_token) return res.status(400).send("missing id_token");
    const idPayload = await OIDC.verifyIdToken({
      id_token: tok.id_token,
      jwks_uri: cfg.jwks_uri,
      issuer,
      client_id: OIDC_CLIENT_ID,
      nonce: st.nonce,
    });

    const roles = OIDC.extractRoles(idPayload, { roleClaim: preset.roleClaim || "roles", groupClaim: preset.groupClaim || "groups" });
    const user = buildUserFromIdTokenPayload(idPayload, roles);

    // create server session
    const sess = sessionStore.create(user, { provider: preset.id, issuer });
    const cookieVal = signCookieValue(SESSION_SECRET, { sid: sess.sid, iat: _nowSecSess() });
    setCookie(res, COOKIE_NAME, cookieVal, { maxAgeSec: SESSION_TTL_SEC });

    // redirect to dashboard
    res.redirect("/dashboard");
  } catch (e) {
    console.error("[OIDC] callback error:", e);
    res.status(500).send("OIDC callback failed");
  }
});

app.get("/logout", (req, res) => {
  try {
    if (req._authSid) sessionStore.destroy(req._authSid);
    clearCookie(res, COOKIE_NAME);
  } catch (_) {}
  res.redirect("/dashboard");
});


function getOtpFromReq(req) {
  const h = req.headers["x-gs-otp"];
  const q = req.query ? req.query.gs_otp : null;
  const b = req.body ? req.body.gsOtp : null;
  return (h || q || b || "").toString().trim();
}

function requireOperatorTotp(requiredRoles) {
  return (req, res, next) => {
    if (!REQUIRE_TOTP) return next();
    if (!OPERATOR_TOTP_SECRET) return res.status(500).json({ ok:false, code:"totp_secret_missing", requestId: req.requestId });
    // Only require OTP for operator/admin actions (not viewer)
    const roles = (req.gsUser && Array.isArray(req.gsUser.roles)) ? req.gsUser.roles : [];
    const need = roles.some(r => (requiredRoles || ["operator","admin"]).includes(r));
    if (!need) return next();
    const otp = getOtpFromReq(req);
    if (!otp) return res.status(401).json({ ok:false, code:"otp_required", message:"OTP required", requestId: req.requestId });
    const ok = verifyTotp(otp, OPERATOR_TOTP_SECRET, { window: OTP_WINDOW, digits: 6, step: 30 });
    if (!ok) return res.status(401).json({ ok:false, code:"otp_invalid", message:"Invalid OTP", requestId: req.requestId });
    return next();
  };
}



// ==========================
// ✅ TOTP gate (non-operator endpoints)
// - For diagnostics-style read-only endpoints that should be protected by mTLS + OTP,
//   but should NOT require operatorKey/OIDC session.
// ==========================
function requireTotpAny() {
  return (req, res, next) => {
    if (!REQUIRE_TOTP) return next();
    if (!OPERATOR_TOTP_SECRET) return res.status(500).json({ ok:false, code:"totp_secret_missing", requestId: req.requestId });
    const otp = getOtpFromReq(req);
    if (!otp) return res.status(401).json({ ok:false, code:"otp_required", message:"OTP required", requestId: req.requestId });
    const ok = verifyTotp(otp, OPERATOR_TOTP_SECRET, { window: OTP_WINDOW, digits: 6, step: 30 });
    if (!ok) return res.status(401).json({ ok:false, code:"otp_invalid", message:"Invalid OTP", requestId: req.requestId });
    return next();
  };
}

// ==========================
// Operator Auth wrapper
// - Accepts either legacy operatorKey (body) OR OIDC cookie session (RBAC)
// ==========================

function _oidcMeetsStepup(user){
  try{
    if (!user) return false;
    const amr = Array.isArray(user.amr) ? user.amr : (user.amr ? [user.amr] : []);
    const lower = amr.map(a=>String(a).toLowerCase());
    for (const need of OIDC_STEPUP_AMR){
      if (lower.includes(need)) return true;
    }
    const acr = String(user.acr||"").toLowerCase();
    if (acr && OIDC_STEPUP_AMR.some(x=>acr.includes(x))) return true;
    return false;
  }catch{ return false; }
}

function operatorOrOidcAuth(requiredRoleSet = ["operator", "admin"]) {
  return (req, res, next) => {
    // Enforce OIDC when required
    if (REQUIRE_OIDC) {
      if (!OIDC_ENABLED) {
        return res.status(500).json({ ok:false, error:"oidc_required_but_disabled" });
      }
      if (!req.user) {
        return res.status(401).json({ ok:false, error:"oidc_required" });
      }
    }

    // OIDC user path
    if (req.user) {
      const presetId = OIDC_PROVIDER;
      // map roles -> operator/admin/viewer based on presets
      // We treat presence of configured operator/admin roles as authorization.
      // If no preset file or no roles, we still allow when user has "admin"/"operator" directly.
      const userRoles = req.user.roles || [];
      const lower = userRoles.map(r => String(r).toLowerCase());
      const isAdmin = lower.includes("admin") || lower.includes("geniesecurity_admin");
      const isOperator = isAdmin || lower.includes("operator") || lower.includes("geniesecurity_operator");
      const isViewer = isOperator || lower.includes("viewer") || lower.includes("geniesecurity_viewer");

      const allowed =
        (requiredRoleSet.includes("admin") && isAdmin) ||
        (requiredRoleSet.includes("operator") && isOperator) ||
        (requiredRoleSet.includes("viewer") && isViewer);

      if (!allowed) return res.status(403).json({ ok: false, error: "rbac_denied" });

      // Optional: require step-up auth (MFA) signal from OIDC claims (amr/acr)
      // If missing, we allow fallback to TOTP OTP when REQUIRE_TOTP=1.
      if (REQUIRE_OIDC_STEPUP) {
        const okStep = _oidcMeetsStepup(req.user);
        if (!okStep) {
          // try TOTP fallback
          const otp = (req.headers["x-gs-otp"] || req.query.gs_otp || "").toString().trim();
          if (!(REQUIRE_TOTP && otp && verifyTotp(otp))) {
            return res.status(403).json({ ok:false, error:"oidc_stepup_required" });
          }
        }
      }

      req._operatorId = req.user.email || req.user.name || req.user.sub || "oidc";
      req._operatorRole = isAdmin ? "OIDC_ADMIN" : (isOperator ? "OIDC_OPERATOR" : "OIDC_VIEWER");
      return requireOperatorTotp(requiredRoleSet)(req, res, next);
    }

    // legacy operator key path
    return operatorAuth(req, res, next);
  };
}

function setSecurityHeaders(res, cspNonce) {
  // Basic hardening headers (no external deps)
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  // CSP with nonce for inline scripts
  const nonce = cspNonce || "";
  const csp = [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "style-src 'self' 'unsafe-inline'",
    `script-src 'self' 'nonce-${nonce}' 'unsafe-inline'`,
    "connect-src 'self'",
  ].join("; ");
  res.setHeader("Content-Security-Policy", csp);
}

async function serveDashboard(req, res) {
  try {
    const nonce = crypto.randomBytes(16).toString("base64");
    setSecurityHeaders(res, nonce);
    const p = path.join(__dirname, "dashboard.html");
    let html = await fsp.readFile(p, "utf8");
    html = html.replace(/__CSP_NONCE__/g, nonce);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(html);
  } catch (e) {
    return res.status(500).send("dashboard_error");
  }
}

// dashboard (static)
// ==========================
app.get("/", (req, res) => serveDashboard(req, res));

// ==========================
// Reports (CSV) + Diagnostics bundle
// - Access controlled via OIDC roles OR legacy operatorKey (unless disabled)
// ==========================
function _csvEscape(v){
  if (v === null || v === undefined) return "";
  const s = String(v);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"' ;
  return s;
}
function _writeCsv(res, filename, header, rows){
  res.setHeader("Content-Type","text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.write(header.join(",") + "\n");
  for (const r of rows){
    res.write(header.map(k => _csvEscape(r[k])).join(",") + "\n");
  }
  res.end();
}


// ==========================
// PDF report helper (no deps): simple single/multi-page text table
// ==========================
function _pdfEscapeText(s){
  return String(s||"").replace(/\\/g,"\\\\").replace(/\(/g,"\\(").replace(/\)/g,"\\)");
}
function _makeSimplePdf(lines, title){
  // Minimal PDF generator: Helvetica, 10pt, 60 lines/page
  const pageLines = 60;
  const fontSize = 10;
  const leading = 12;
  const left = 40;
  const top = 800;
  const pages = [];
  const header = title ? [`${title}`,""] : [];
  const all = header.concat(lines);
  for (let i=0;i<all.length;i+=pageLines){
    pages.push(all.slice(i,i+pageLines));
  }
  const objects = [];
  function addObj(str){ objects.push(str); return objects.length; }
  // 1) catalog, 2) pages will be later
  const kids = [];
  // font object
  const fontObjNum = addObj(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`);
  for (let p=0;p<pages.length;p++){
    const page = pages[p];
    let content = "BT\n";
    content += `/F1 ${fontSize} Tf\n`;
    let y = top;
    for (const ln of page){
      content += `${left} ${y} Td (${_pdfEscapeText(ln)}) Tj\n`;
      y -= leading;
    }
    content += "ET\n";
    const contentStream = `<< /Length ${Buffer.byteLength(content,"utf8")} >>\nstream\n${content}endstream`;
    const contentObjNum = addObj(contentStream);
    const pageObj = `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 ${fontObjNum} 0 R >> >> /MediaBox [0 0 595 842] /Contents ${contentObjNum} 0 R >>`;
    const pageObjNum = addObj(pageObj);
    kids.push(`${pageObjNum} 0 R`);
  }
  const pagesObj = `<< /Type /Pages /Count ${kids.length} /Kids [ ${kids.join(" ")} ] >>`;
  // Insert pages object as #2: we built others first, so adjust by adding at beginning is hard.
  // We'll rebuild with fixed ordering:
  const objs = [];
  // 1 catalog, 2 pages, 3 font, then pairs of content/page
  objs.push(""); // placeholder
  objs.push(""); // placeholder
  objs.push(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>`);
  const pageRefs = [];
  for (let p=0;p<pages.length;p++){
    const page = pages[p];
    let content = "BT\n";
    content += `/F1 ${fontSize} Tf\n`;
    let y = top;
    for (const ln of page){
      content += `${left} ${y} Td (${_pdfEscapeText(ln)}) Tj\n`;
      y -= leading;
    }
    content += "ET\n";
    const contentStream = `<< /Length ${Buffer.byteLength(content,"utf8")} >>\nstream\n${content}endstream`;
    objs.push(contentStream);
    const contentNum = objs.length;
    const pageObj = `<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 3 0 R >> >> /MediaBox [0 0 595 842] /Contents ${contentNum} 0 R >>`;
    objs.push(pageObj);
    pageRefs.push(`${objs.length} 0 R`);
  }
  objs[1] = `<< /Type /Catalog /Pages 2 0 R >>`;
  objs[2] = `<< /Type /Pages /Count ${pageRefs.length} /Kids [ ${pageRefs.join(" ")} ] >>`;
  // write xref
  let out = "%PDF-1.4\n";
  const offsets = [0];
  for (let i=1;i<objs.length;i++){
    offsets[i] = Buffer.byteLength(out,"utf8");
    out += `${i} 0 obj\n${objs[i]}\nendobj\n`;
  }
  const xrefStart = Buffer.byteLength(out,"utf8");
  out += "xref\n";
  out += `0 ${objs.length}\n`;
  out += "0000000000 65535 f \n";
  for (let i=1;i<objs.length;i++){
    out += String(offsets[i]).padStart(10,"0") + " 00000 n \n";
  }
  out += "trailer\n";
  out += `<< /Size ${objs.length} /Root 1 0 R >>\n`;
  out += "startxref\n";
  out += `${xrefStart}\n%%EOF\n`;
  return Buffer.from(out,"utf8");
}
function _loadReportSigningKey(){
  try { return fs.readFileSync(REPORT_SIGNING_KEY_PATH, "utf8"); } catch { return null; }
}
function _signReportPdf(pdfBuf){
  try{
    const pem = _loadReportSigningKey();
    if (!pem) return null;
    const hash = crypto.createHash("sha256").update(pdfBuf).digest();
    const sig = crypto.sign(null, hash, pem);
    return sig.toString("base64");
  }catch{ return null; }
}

// Sessions report
app.get("/api/reports/sessions.csv", operatorOrOidcAuth(["auditor","operator","admin"]), async (req, res) => {
  try {
    const raw = await fsp.readFile(SESSIONS_PATH, "utf-8").catch(()=>"{\"sessions\":{}}");
    const obj = JSON.parse(raw || "{}");
    const sessions = obj.sessions || obj || {};
    const rows = [];
    for (const [sid, s] of Object.entries(sessions)) {
      if (!s || typeof s !== "object") continue;
      rows.push({
        sessionId: sid,
        status: s.status || "",
        serverUuid: s.serverUuid || "",
        clientUuid: s.clientUuid || "",
        assignedPort: s.assignedPort || "",
        clientIp: s.clientIp || "",
        requestedAt: s.requestedAt || "",
        openedAt: s.openedAt || "",
        expiresAt: s.expiresAt || "",
        closedAt: s.closedAt || "",
        closeReason: s.closeReason || "",
      });
    }
    rows.sort((a,b)=>(b.requestedAt||0)-(a.requestedAt||0));
    const header = ["sessionId","status","serverUuid","clientUuid","assignedPort","clientIp","requestedAt","openedAt","expiresAt","closedAt","closeReason"];
    return _writeCsv(res, "sessions.csv", header, rows);
  } catch (e) {
    return res.status(500).json({ ok:false, error:"report_failed", detail:String(e.message||e) });
  }
});

// Audit report (JSONL -> CSV)
app.get("/api/reports/audit.csv", operatorOrOidcAuth(["auditor","operator","admin"]), async (req, res) => {
  try {
    const text = await fsp.readFile(AUDIT_LOG_PATH, "utf-8").catch(()=> "");
    const lines = text.split(/\r?\n/).filter(Boolean);
    const rows = [];
    for (const ln of lines) {
      let o; try { o = JSON.parse(ln); } catch { continue; }
      const d = o.data || {};
      rows.push({
        ts: o.ts || "",
        type: o.type || "",
        actor: o.actor || "",
        sessionId: d.sessionId || d.sid || "",
        serverUuid: d.serverUuid || "",
        clientUuid: d.clientUuid || "",
        clientIp: d.clientIp || "",
        assignedPort: d.assignedPort || "",
        expiresAt: d.expiresAt || "",
        detail: JSON.stringify(d),
      });
    }
    const header = ["ts","type","actor","sessionId","serverUuid","clientUuid","clientIp","assignedPort","expiresAt","detail"];
    return _writeCsv(res, "audit.csv", header, rows);
  } catch (e) {
    return res.status(500).json({ ok:false, error:"report_failed", detail:String(e.message||e) });
  }
});


// Sessions report PDF
app.get("/api/reports/sessions.pdf", operatorOrOidcAuth(["auditor","operator","admin"]), async (req, res) => {
  try {
    const raw = await fsp.readFile(SESSIONS_PATH, "utf-8").catch(()=>"{\"sessions\":{}}");
    const obj = JSON.parse(raw || "{}");
    const sessions = obj.sessions || obj || {};
    const rows = [];
    for (const [sid, s] of Object.entries(sessions)) {
      if (!s || typeof s !== "object") continue;
      rows.push({
        sessionId: sid,
        status: s.status || "",
        serverUuid: s.serverUuid || "",
        clientUuid: s.clientUuid || "",
        assignedPort: s.assignedPort || "",
        requestedAt: s.requestedAt || "",
        openedAt: s.openedAt || "",
        expiresAt: s.expiresAt || "",
        closedAt: s.closedAt || "",
        closeReason: s.closeReason || "",
      });
    }
    rows.sort((a,b)=>(b.requestedAt||0)-(a.requestedAt||0));
    const lines = [];
    lines.push("sessionId | status | serverUuid | clientUuid | port | requestedAt | openedAt | expiresAt | closedAt | closeReason");
    lines.push("-".repeat(110));
    for (const r of rows.slice(0, 500)) {
      lines.push(`${r.sessionId} | ${r.status} | ${r.serverUuid} | ${r.clientUuid} | ${r.assignedPort} | ${r.requestedAt} | ${r.openedAt} | ${r.expiresAt} | ${r.closedAt} | ${r.closeReason}`);
    }
    const pdf = _makeSimplePdf(lines, "GenieSecurity Sessions Report");
    const sigB64 = _signReportPdf(pdf);
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=\"sessions.pdf\"");
    res.setHeader("x-gs-report-sha256", crypto.createHash("sha256").update(pdf).digest("hex"));
    if (sigB64) res.setHeader("x-gs-report-signature", sigB64);
    return res.end(pdf);
  } catch (e) {
    return res.status(500).json({ ok:false, error:"report_failed", detail:String(e.message||e) });
  }
});

// Audit report PDF
app.get("/api/reports/audit.pdf", operatorOrOidcAuth(["auditor","operator","admin"]), async (req, res) => {
  try {
    const text = await fsp.readFile(AUDIT_LOG_PATH, "utf-8").catch(()=> "");
    const lines0 = text.split(/\r?\n/).filter(Boolean);
    const lines = [];
    lines.push("ts | type | actor | sessionId | serverUuid | clientUuid | clientIp | port | expiresAt | detail");
    lines.push("-".repeat(110));
    for (const ln of lines0.slice(-1000)) {
      let o; try { o = JSON.parse(ln); } catch { continue; }
      const d = o.data || {};
      lines.push(`${o.ts||""} | ${o.type||""} | ${o.actor||""} | ${(d.sessionId||d.sid||"")} | ${(d.serverUuid||"")} | ${(d.clientUuid||"")} | ${(d.clientIp||"")} | ${(d.assignedPort||"")} | ${(d.expiresAt||"")} | ${JSON.stringify(d)}`);
    }
    const pdf = _makeSimplePdf(lines, "GenieSecurity Audit Report");
    const sigB64 = _signReportPdf(pdf);
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=\"audit.pdf\"");
    res.setHeader("x-gs-report-sha256", crypto.createHash("sha256").update(pdf).digest("hex"));
    if (sigB64) res.setHeader("x-gs-report-signature", sigB64);
    return res.end(pdf);
  } catch (e) {
    return res.status(500).json({ ok:false, error:"report_failed", detail:String(e.message||e) });
  }
});

// ==========================
// ✅ Compliance evidence PDF (Zero Trust / PAM mapping)
// ==========================
app.get("/api/reports/compliance.pdf", operatorOrOidcAuth(["auditor","operator","admin"]), async (req, res) => {
  try {
    const envSnap = {
      COOKIE_SECURE: process.env.COOKIE_SECURE,
      TRUST_PROXY_MODE: process.env.TRUST_PROXY_MODE,
      JSON_LIMIT: process.env.JSON_LIMIT,
      ENFORCE_DEVICE_ALLOWLIST: process.env.ENFORCE_DEVICE_ALLOWLIST,
      AUDIT_SIGNING_PRIV_B64: process.env.AUDIT_SIGNING_PRIV_B64 ? "[SET]" : "",
      RISK_ENABLED: process.env.RISK_ENABLED,
      RISK_AUTO_APPROVE_MAX_SCORE: process.env.RISK_AUTO_APPROVE_MAX_SCORE,
      RISK_BUSINESS_HOUR_START: process.env.RISK_BUSINESS_HOUR_START,
      RISK_BUSINESS_HOUR_END: process.env.RISK_BUSINESS_HOUR_END,
      RISK_IP_ALLOW_CIDRS: process.env.RISK_IP_ALLOW_CIDRS,
    };

    // policy signature enforcement is determined by presence of POLICY_PUBKEY (server.cjs self-check uses this rule)
    const policySignatureEnforced = !!process.env.POLICY_PUBKEY;
    const auditSigningEnforced = String(process.env.AUDIT_REQUIRE_SIGNING || "0") === "1";
    const lines = buildComplianceLines({
      env: envSnap,
      siemStatus: SIEM.status(),
      policySignatureEnforced,
      auditSigningEnforced,
    });

    const pdf = _makeSimplePdf(lines, "GenieSecurity Compliance Evidence Pack");
    const sigB64 = _signReportPdf(pdf);
    res.setHeader("Content-Type","application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=\"compliance.pdf\"");
    res.setHeader("x-gs-report-sha256", crypto.createHash("sha256").update(pdf).digest("hex"));
    if (sigB64) res.setHeader("x-gs-report-signature", sigB64);
    return res.end(pdf);
  } catch (e) {
    return res.status(500).json({ ok:false, error:"report_failed", detail:String(e.message||e) });
  }
});


// Diagnostics bundle: packs key files + last logs + audit verify report
app.post("/api/diagnostics/bundle", operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    const ts = new Date().toISOString().replace(/[:.]/g,"-");
    const tmpDir = path.join(os.tmpdir ? os.tmpdir() : path.join(__dirname,"..","tmp"), `gs_diag_${ts}`);
    await fsp.mkdir(tmpDir, { recursive: true });
    // copy key data/config
    await _copyIfExists(SESSIONS_PATH, path.join(tmpDir,"sessions.json"));
    await _copyIfExists(USERS_PATH, path.join(tmpDir,"users.json"));
    await _copyIfExists(REGISTRY_PATH, path.join(tmpDir,"registry.json"));
    await _copyIfExists(POLICY_PATH, path.join(tmpDir,"policy.json"));
    await _copyIfExists(AUDIT_LOG_PATH, path.join(tmpDir,"audit.jsonl"));
    // recent logs
    const recentRelayLogs = _listRecentLogFiles(LOG_DIR, 5);
    const logsDir = path.join(tmpDir,"logs");
    await fsp.mkdir(logsDir, { recursive: true });
    for (const it of recentRelayLogs) await _copyIfExists(it.full, path.join(logsDir,it.fn));
    // evidence readme + manifest (hashes)
    const evidenceReadme = [
      "GenieSecurity Diagnostics Evidence Bundle",
      `CreatedAt: ${new Date().toISOString()}`,
      `RequestId: ${req._requestId || ""}`,
      "",
      "Contains: sessions/users/registry/policy/audit + recent logs + verification hints.",
      "Note: secrets may be redacted depending on build/config.",
      "",
    ].join("\n");
    await fsp.writeFile(path.join(tmpDir,"EVIDENCE_README.txt"), evidenceReadme, "utf8");
    // build sha256 manifest for included files
    const manifest = { createdAt: new Date().toISOString(), requestId: req._requestId || "", files: {} };
    async function _hashFile(p){
      const b = await fsp.readFile(p);
      return crypto.createHash("sha256").update(b).digest("hex");
    }
    const toHash = [
      path.join(tmpDir,"sessions.json"),
      path.join(tmpDir,"users.json"),
      path.join(tmpDir,"registry.json"),
      path.join(tmpDir,"policy.json"),
      path.join(tmpDir,"audit.jsonl"),
      path.join(tmpDir,"EVIDENCE_README.txt"),
    ];
    for (const p of toHash){
      try { manifest.files[path.basename(p)] = await _hashFile(p); } catch {}
    }
    // hash recent logs too
    try {
      const logFiles = await fsp.readdir(logsDir).catch(()=>[]);
      for (const fn of logFiles){
        const p = path.join(logsDir, fn);
        manifest.files[`logs/${fn}`] = await _hashFile(p);
      }
    } catch {}
    await fsp.writeFile(path.join(tmpDir,"evidence_manifest.json"), JSON.stringify(manifest,null,2), "utf8");

    // verify audit
    await _runVerifyAudit(tmpDir).catch(()=>{});
    const manifest2 = { ts, files: { sessions: path.basename(SESSIONS_PATH), audit: path.basename(AUDIT_LOG_PATH) } };
    await fsp.writeFile(path.join(tmpDir,"manifest.json"), JSON.stringify(manifest2,null,2),"utf-8");
    const outName = `diagnostics_${ts}.zip`;
    const outZip = path.join(EVIDENCE_DIR, outName);
    const cp = require("child_process");
    await new Promise((resolve, reject) => {
      const args = ["-a","-c","-f", outZip, "-C", tmpDir, "."];
      cp.execFile("tar", args, { windowsHide:true, timeout:60_000 }, (err, stdout, stderr) => {
        if (err) return reject(new Error(`tar_failed: ${String(stderr||stdout||err.message||err)}`));
        resolve();
      });
    });
    return res.json({ ok:true, bundle: `/evidence/${outName}` });
  } catch (e) {
    return res.status(500).json({ ok:false, error:"diag_failed", detail:String(e.message||e) });
  }
});

// ==========================
// Diagnostics: one-click self-check (healthz + audit verify + policy verify)
// ==========================
app.get("/api/diagnostics/self-check", requireTotpAny(), async (req, res) => {
  const checks = [];
  const add = (name, status, detail) => checks.push({ name, status, detail: (detail||"") });

  try {
    // 1) healthz (if we are here, server is alive)
    add("healthz", "PASS", "Relay HTTP is responding.");

    // 2) audit chain verify (optional if file exists)
    try {
      const auditAbs = path.resolve(AUDIT_LOG_PATH);
      if (!fs.existsSync(auditAbs)) {
        add("audit_chain", "WARN", "audit.jsonl not found (no events yet).");
      } else {
        const script = path.resolve(ROOT_DIR, "scripts", "verify_audit_chain.cjs");
        const { execFile } = require("child_process");
        const out = await new Promise((resolve) => {
          execFile(process.execPath, [script, auditAbs], { timeout: 15000 }, (err, stdout, stderr) => {
            resolve({ err, stdout: String(stdout||""), stderr: String(stderr||"") });
          });
        });
        if (out.err) {
          add("audit_chain", "FAIL", (out.stderr || out.stdout || out.err.message || "verify failed"));
        } else {
          add("audit_chain", "PASS", (out.stdout.trim() || "OK"));
        }
      }
    } catch (e) {
      add("audit_chain", "FAIL", String(e && e.message ? e.message : e));
    }

    // 3) policy syntax + signature verify (signature is optional)
    try {
      const policyAbs = path.resolve(POLICY_PATH);
      if (!fs.existsSync(policyAbs)) {
        add("policy", "WARN", "policy.json not found.");
      } else {
        const policyBuf = fs.readFileSync(policyAbs);
        // syntax check
        JSON.parse(policyBuf.toString("utf-8"));
        // minimal evaluator smoke test (does not enforce allow/deny)
        try {
          evaluatePolicy({ nowSec: nowSec(), clientIp: "127.0.0.1", serverUuid: "selfcheck", port: 22, clientUuid: "selfcheck" }, {});
        } catch (_) { /* ignore */ }

        const pubB64 = process.env.POLICY_PUBKEY || "";
        if (!pubB64) {
          add("policy_signature", "WARN", "POLICY_PUBKEY not set (signature verification disabled).");
        } else {
          const sigPath = policyAbs + ".sig";
          if (!fs.existsSync(sigPath)) {
            add("policy_signature", "FAIL", "POLICY_PUBKEY is set but policy.json.sig is missing.");
          } else {
            const sigB64 = fs.readFileSync(sigPath, "utf-8").trim();
            const pubDer = Buffer.from(pubB64, "base64");
            const ok = crypto.verify(
              null,
              policyBuf,
              crypto.createPublicKey({ key: pubDer, format: "der", type: "spki" }),
              Buffer.from(sigB64, "base64")
            );
            if (!ok) add("policy_signature", "FAIL", "policy signature verification failed.");
            else add("policy_signature", "PASS", "policy signature verified.");
          }
        }
        add("policy", "PASS", "policy.json parsed.");
      }
    } catch (e) {
      add("policy", "FAIL", String(e && e.message ? e.message : e));
    }

    const summary = checks.some(c => c.status === "FAIL") ? "FAIL" : (checks.some(c => c.status === "WARN") ? "WARN" : "PASS");
    return res.json({ ok: true, summary, checks, requestId: req.requestId });
  } catch (e) {
    return res.status(500).json({ ok: false, code: "self_check_failed", message: String(e && e.message ? e.message : e), requestId: req.requestId });
  }
});

app.get("/dashboard", (req, res) => serveDashboard(req, res));


// ==========================
// ✅ API: audit (dashboard용)
// ==========================
app.get("/api/audit", async (req, res) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit, 10) : 200;
    const sessionId = (req.query.sessionId || "").trim();

    const rows = await readAuditLines(Number.isFinite(limit) ? limit : 200);

    let out = rows;
    if (sessionId) {
      out = rows.filter(r => {
        const d = r && r.details ? r.details : {};
        return d.sessionId === sessionId;
      });
    }

    res.json({ ok: true, count: out.length, rows: out });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// API: registry
// ==========================
app.post("/api/register/server", async (req, res) => {
  try {
    const { serverUuid, serverPsk } = req.body || {};

    needUuid(serverUuid, "serverUuid");
    needStr(serverPsk, "serverPsk", 512);
    if (!serverUuid || !serverPsk) return res.status(400).json({ ok: false, error: "missing_fields" });

    servers[serverUuid] = {
      serverUuid,
      serverPsk,
      createdAt: nowSec(),
    };

    await saveRegistry();
    await appendAudit("SERVER_REGISTERED", { serverUuid });

    res.json({ ok: true, serverUuid });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ Step2: SERVER_TOKEN 제거 → 공개키 기반 서버 인증
// - register-intent: 무신뢰 등록(공개키만 제출) -> PENDING
// - operator approve-server: 운영자 승인 시 ACTIVE
// - 서버 공개키는 32바이트 RAW(Base64) 로 저장
// ==========================
app.post("/api/server/register-intent", async (req, res) => {
  try {
    const { serverUuid, kid, pub, sigPub } = req.body || {};
    if (!serverUuid || !kid || !pub) return res.status(400).json({ ok: false, error: "missing_fields" });

    // pub 검증(32 bytes raw)
    const raw = Buffer.from(String(pub), "base64");
    if (raw.length !== 32) return res.status(400).json({ ok: false, error: "invalid_pub_raw" });

    // sigPub 검증(Ed25519 pub 32 bytes raw)
    if (!sigPub) return res.status(400).json({ ok: false, error: "missing_sig_pub" });
    const sigRaw = Buffer.from(String(sigPub), "base64");
    if (sigRaw.length !== 32) return res.status(400).json({ ok: false, error: "invalid_sig_pub_raw" });


    const prev = servers[serverUuid] || null;

    servers[serverUuid] = {
      ...(prev || {}),
      serverUuid,
      kid: String(kid).trim(),
      pub: String(pub).trim(),
      sigPub: String(sigPub).trim(),
      status: (prev && prev.status) ? prev.status : "PENDING",
      updatedAt: nowSec(),
      createdAt: (prev && prev.createdAt) ? prev.createdAt : nowSec(),
    };

    await saveRegistry();
    await appendAudit("SERVER_REGISTER_INTENT", { serverUuid, kid: String(kid).trim(), status: servers[serverUuid].status });

    res.json({ ok: true, serverUuid, status: servers[serverUuid].status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// 운영자 승인: PENDING -> ACTIVE
app.post("/api/operator/approve-server", requireSameOrigin, operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    const { serverUuid } = req.body || {};

    const operatorId = (req && (req.operatorId || (req.user && (req.user.preferred_username || req.user.sub)))) || process.env.OPERATOR_ID || "unknown";
    const pol = evaluatePolicy({
      event: "OPERATOR_ACTION",
      action: "SERVER_APPROVE",
      operatorId,
      operatorIp: getRealIp(req),
      serverUuid,
    });
    if (!pol.ok) {
      await appendAudit("POLICY_DENY", { action: "SERVER_APPROVE", serverUuid, operatorId, reason: pol.reason });
      return res.status(403).json({ ok: false, error: "policy_denied", reason: pol.reason });
    }

    const s = servers[serverUuid];
    if (!s) return res.status(404).json({ ok: false, error: "server_not_registered" });


    // ✅ idempotency replay
    const idemKey = getIdemKey(req);
    if (idemKey) {
      const rec = idemLookup(s, "approve-server", idemKey);
      if (rec) return idemReplay(res, rec);
    }

    s.status = "ACTIVE";
    s.approvedAt = nowSec();

    await saveRegistry();
    await appendAudit("SERVER_APPROVED", { serverUuid });

    res.json({ ok: true, serverUuid, status: s.status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.post("/api/register/client", async (req, res) => {
  try {
    const { clientUuid, clientPsk } = req.body || {};

    needUuid(clientUuid, "clientUuid");
    needStr(clientPsk, "clientPsk", 512);
    if (!clientUuid || !clientPsk) return res.status(400).json({ ok: false, error: "missing_fields" });

    clients[clientUuid] = {
      clientUuid,
      clientPsk,
      createdAt: nowSec(),
    };

    await saveRegistry();
    await appendAudit("CLIENT_REGISTERED", { clientUuid });

    res.json({ ok: true, clientUuid });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ API: client report-connect-test (client_agent용)
// ==========================
app.post("/api/client/report-connect-test", async (req, res) => {
  try {
    const { sessionId, ok, message, meta } = req.body || {};
    await appendAudit("CLIENT_CONNECT_TEST", {
      sessionId,
      ok: !!ok,
      message: message || "",
      meta: meta || {},
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ API: client report-event (client_agent용)
// ==========================
app.post("/api/client/report-event", async (req, res) => {
  try {
    const { sessionId, event, message, meta } = req.body || {};
    await appendAudit("CLIENT_EVENT", {
      sessionId,
      event: event || "",
      message: message || "",
      meta: meta || {},
    });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ (NEW) [프롬프트8] API: client report-ip-change
// - client agent가 IP 변경을 감지했을 때 서버에게 보고
// - 서버가 정책 기반으로 KEEP_SESSION / RE_REQUEST 를 결정
// - 기존 로직 변경 없음 (추가 endpoint)
// body: { sessionId, clientUuid, serverUuid, oldIp, newIp, meta }
// resp: { ok:true, action:"KEEP_SESSION"|"RE_REQUEST", reason, policy }
app.post("/api/client/report-ip-change", async (req, res) => {
  try {
    let ipInfo;
    try {
      ipInfo = resolveClientIpOrThrow(req);
      const { deviceFingerprint, deviceInfo } = req.body || {};
      const clientUuidForDevice = (req.body || {}).clientUuid;
      if (!(await enforceDeviceAllowlist("client", clientUuidForDevice, deviceFingerprint, deviceInfo, res, { ip: ipInfo.clientIp }))) return;
    } catch (err) {
      await appendAudit("IP_CHANGE_REPORT_BLOCKED", {
        reason: err.code || "ip_resolution_failed",
        message: err.message,
        meta: err.meta || {},
        remoteAddr: extractRemoteAddress(req),
        xff: getHeader(req, "x-forwarded-for") || "",
        cfConnectingIp: getHeader(req, "cf-connecting-ip") || "",
        trueClientIp: getHeader(req, "true-client-ip") || "",
      });
      return res.status(403).json({ ok: false, error: err.code || "ip_change_report_blocked" });
    }

    const reportIp = ipInfo.clientIp;

    const { sessionId, clientUuid, serverUuid, oldIp, newIp, meta } = req.body || {};
    if (!sessionId || !clientUuid || !serverUuid || !newIp) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    // rate limit도 적용(오남용 방지)
    try {
      await enforceRateLimitOrThrow(reportIp, clientUuid);
    } catch (err) {
      const meta2 = err.meta || {};
      return res.status(429).json({ ok: false, error: err.code || "rate_limited", meta: meta2 });
    }

    const s = sessions[sessionId];

    // 세션이 없거나 mismatch면 정보 최소화 + audit만
    if (!s) {
      await appendAudit("IP_CHANGE_REPORTED", {
        sessionId,
        clientUuid,
        serverUuid,
        oldIp: oldIp || "",
        newIp,
        reportIp,
        result: "session_not_found",
        meta: meta || {},
      });
      return res.json({
        ok: true,
        action: "RE_REQUEST",
        policy: "NO_SESSION",
        reason: "session_not_found",
      });
    }

    if (s.clientUuid !== clientUuid || s.serverUuid !== serverUuid) {
      await appendAudit("IP_CHANGE_REPORTED", {
        sessionId,
        clientUuid,
        serverUuid,
        oldIp: oldIp || "",
        newIp,
        reportIp,
        result: "uuid_mismatch",
        sessionClientUuid: s.clientUuid,
        sessionServerUuid: s.serverUuid,
        meta: meta || {},
      });
      return res.json({
        ok: true,
        action: "RE_REQUEST",
        policy: "UUID_MISMATCH",
        reason: "uuid_mismatch",
      });
    }

    const t = nowSec();

    // 이미 만료/거절된 세션은 새 요청 권장
    if (s.status === "EXPIRED" || s.status === "REJECTED") {
      await appendAudit("IP_CHANGE_REPORTED", {
        sessionId,
        clientUuid,
        serverUuid,
        oldIp: oldIp || s.clientIp || "",
        newIp,
        reportIp,
        result: "terminal_status",
        status: s.status,
        meta: meta || {},
      });
      return res.json({
        ok: true,
        action: "RE_REQUEST",
        policy: "TERMINAL_STATUS",
        reason: "expired_or_rejected",
      });
    }

    // 정책: 기본은 RE_REQUEST (세션 하이재킹 방지)
    // 단, newIp가 Triple Whitelist에 매칭되면 KEEP_SESSION 허용
    const match = matchAutoApproveTriple(clientUuid, serverUuid, newIp);

    let action = "RE_REQUEST";
    let policy = "DEFAULT_RE_REQUEST";
    let reason = "ip_changed_re_request";

    if (match && match.ok) {
      action = "KEEP_SESSION";
      policy = match.policy;
      reason = match.reason;
    }

    // 세션에 이력만 추가(기존 필드 변경 최소)
    if (!s.ipChangeHistory) s.ipChangeHistory = [];
    s.ipChangeHistory.push({
      ts: t,
      oldIp: oldIp || s.clientIp || "",
      newIp: newIp,
      reportIp,
      action,
      policy,
      ruleId: match && match.ok ? match.ruleId : undefined,
      meta: meta || {},
    });

    await saveSessions();

    await appendAudit("CLIENT_IP_CHANGED", {
      sessionId,
      clientUuid,
      serverUuid,
      oldIp: oldIp || s.clientIp || "",
      newIp,
      reportIp,
      action,
      policy,
      ruleId: match && match.ok ? match.ruleId : undefined,
      reason,
      meta: meta || {},
    });

    return res.json({
      ok: true,
      action,
      policy,
      reason,
      ruleId: match && match.ok ? match.ruleId : undefined,
    });
  } catch (e) {
    await appendAudit("IP_CHANGE_API_ERROR", { error: e.message });
    return res.json({ ok: false, error: "internal_error" });
  }
});

// ==========================
// ✅ (NEW) 중복 세션 재사용 유틸
// ==========================

function countOpenedSessionsForServer(serverUuid) {
  let c = 0;
  for (const sid of Object.keys(sessions)) {
    const s = sessions[sid];
    if (!s) continue;
    if (s.serverUuid !== serverUuid) continue;
    if (s.status !== "OPENED") continue;
    const exp = typeof s.expiresAt === "number" ? s.expiresAt : 0;
    if (exp && exp <= nowSec()) continue;
    c++;
  }
  return c;
}

function findReusableSession(clientUuid, serverUuid, clientIp) {
  const t = nowSec();
  let opened = null;
  let pending = null;

  for (const sid of Object.keys(sessions)) {
    const s = sessions[sid];
    if (!s) continue;
    if (s.clientUuid !== clientUuid) continue;
    if (s.serverUuid !== serverUuid) continue;
    if (s.clientIp !== clientIp) continue;
    if (s.status !== "OPENED" && s.status !== "PENDING") continue;
    if (typeof s.expiresAt === "number" && s.expiresAt <= t) continue;

    if (s.status === "OPENED") {
      opened = s;
      break;
    }
    if (s.status === "PENDING") {
      pending = s;
    }
  }

  return opened || pending;
}

// ==========================
// ✅ (NEW) confirm-open 1회 소비
// ==========================
function findConsumableOpenedSessionForServer(serverUuid) {
  const t = nowSec();
  for (const sid of Object.keys(sessions)) {
    const s = sessions[sid];
    if (!s) continue;
    if (s.serverUuid !== serverUuid) continue;
    if (s.status !== "OPENED") continue;
    if (typeof s.expiresAt === "number" && s.expiresAt <= t) continue;
    if (typeof s.consumedAt === "number") continue;
    return s;
  }
  return null;
}

function isRetryAfterSec(resetAt) {
  const t = nowSec();
  const r = Math.max(1, (resetAt || t) - t);
  return r;
}

// ==========================
// API: request-access (client)
// ==========================
app.post("/api/client/request-access", async (req, res) => {
  try {
    let ipInfo;
    try {
      ipInfo = resolveClientIpOrThrow(req);
      const { deviceFingerprint, deviceInfo } = req.body || {};
      const clientUuidForDevice = (req.body || {}).clientUuid;
      if (!(await enforceDeviceAllowlist("client", clientUuidForDevice, deviceFingerprint, deviceInfo, res, { ip: ipInfo.clientIp }))) return;
    } catch (err) {
      await appendAudit("ACCESS_REQUEST_BLOCKED", {
        reason: err.code || "ip_resolution_failed",
        message: err.message,
        meta: err.meta || {},
        remoteAddr: extractRemoteAddress(req),
        xff: getHeader(req, "x-forwarded-for") || "",
        cfConnectingIp: getHeader(req, "cf-connecting-ip") || "",
        trueClientIp: getHeader(req, "true-client-ip") || "",
      });
      return res.status(403).json({ ok: false, error: err.code || "access_request_blocked" });
    }

    const ip = ipInfo.clientIp;

    const { clientUuid, serverUuid } = req.body || {};
    if (!clientUuid || !serverUuid) return denyWithDelay(req, res, ipInfo, "missing_fields", {});

    try {
      await enforceRateLimitOrThrow(ip, clientUuid);
    } catch (err) {
      const meta = err.meta || {};
      if (meta && typeof meta.resetAt === "number") {
        res.set("Retry-After", String(isRetryAfterSec(meta.resetAt)));
      }
      return res.status(429).json({
        ok: false,
        error: err.code || "rate_limited",
        meta,
      });

// ✅ P0-1: clientPsk Proof-of-Possession (PoP) verify (Always-Closed)
const popOk = await verifyClientPoPOrDeny(req, res, ipInfo);
if (popOk !== true) return;

    }

    if (!clients[clientUuid]) return denyWithDelay(req, res, ipInfo, "client_not_registered", {});
    if (!servers[serverUuid]) return denyWithDelay(req, res, ipInfo, "server_not_registered", {});

    const reusable = findReusableSession(clientUuid, serverUuid, ip);
    if (reusable) {
      await appendAudit("ACCESS_REQUEST_REUSED", {
        sessionId: reusable.sessionId,
        clientUuid,
        serverUuid,
        clientIp: ip,
        status: reusable.status,
        assignedPort: reusable.assignedPort,
        expiresAt: reusable.expiresAt,
      });

      return res.json({
        ok: true,
        sessionId: reusable.sessionId,
        status: reusable.status,
        autoApproved: reusable.status === "OPENED",
        expiresAt: reusable.expiresAt,
        reused: true,
      });
    }

    const sid = newSessionId();
    const assignedPort = allocatePort();
    const t = nowSec();

    // ✅ 기존 Pair autoApprove 유지
    const autoApprovedPair = isAutoApprovePair(clientUuid, serverUuid);

    // ✅ (추가 강화) Triple whitelist 매칭
    const tripleMatch = matchAutoApproveTriple(clientUuid, serverUuid, ip);
    const autoApprovedTriple = !!(tripleMatch && tripleMatch.ok);

    // ✅ 최종 autoApproved (기존 + 강화)
    const autoApprovedByWhitelist = autoApprovedTriple || autoApprovedPair;

    // ✅ (NEW) Risk-based scoring/auto-approval (unattended option)
    const riskEnabled = String(process.env.RISK_ENABLED || "0") === "1";
    let risk = null;
    if (riskEnabled) {
      try {
        const policy = loadRiskPolicyFromEnv(process.env);
        const auditLines = await readAuditLines(500);
        const { deviceFingerprint } = (req.body || {});
        risk = computeRisk({
          clientUuid,
          serverUuid,
          clientIp: ip,
          nowSec: t,
          sessions,
          auditLines,
          policy,
          deviceFingerprint,
        });
      } catch (e) {
        risk = null;
      }
    }

    

    // ✅ concurrency policy: if server already has enough OPENED sessions, do not auto-open
    let autoApprovedFinal = autoApprovedByWhitelist;
    if (autoApprovedFinal) {
      const openedCnt = countOpenedSessionsForServer(serverUuid);
      if (openedCnt >= MAX_OPENED_PER_SERVER) {
        autoApprovedFinal = false;
        await appendAudit("AUTO_APPROVE_BLOCKED_BY_CONCURRENCY", { serverUuid, clientUuid, clientIp: ip, opened: openedCnt, max: MAX_OPENED_PER_SERVER });
      }
    }

    // ✅ Risk auto-approve (only if not already approved by whitelist)
    let autoApprovedByRisk = false;
    if (!autoApprovedFinal && risk && risk.autoApprove) {
      autoApprovedFinal = true;
      autoApprovedByRisk = true;
    }

const status = autoApprovedFinal ? "OPENED" : "PENDING";
    const ttl = autoApprovedFinal ? AUTO_APPROVE_TTL_SEC : DEFAULT_OPEN_TTL_SEC;

    sessions[sid] = {
      sessionId: sid,
      status,
      clientUuid,
      serverUuid,
      clientIp: ip,
      assignedPort,
      createdAt: t,
      expiresAt: t + ttl,

      warnedAt: undefined,
      extendCount: 0,
      extendedAt: undefined,
      closeEnforcedAt: undefined,

      consumedAt: undefined,

      openToken: undefined,
      openTokenIssuedAt: undefined,
      openTokenJti: undefined,

      // ✅ (추가) autoApprove 근거(추가 필드이므로 기존 영향 없음)
      autoApproved: autoApprovedFinal,
      autoApprovedByWhitelist: autoApprovedByWhitelist,
      autoApprovedByRisk: autoApprovedByRisk,
      autoApprovedPolicy: autoApprovedByRisk
        ? "RISK_SCORE"
        : (autoApprovedTriple ? (tripleMatch.policy || "WHITELIST_TRIPLE") : (autoApprovedPair ? "PAIR_WHITELIST" : "")),
      autoApprovedRuleId: autoApprovedByRisk
        ? ""
        : (autoApprovedTriple ? (tripleMatch.ruleId || "") : ""),
      autoApprovedReason: autoApprovedByRisk
        ? (risk ? (`score=${risk.score} tier=${risk.tier} reasons=${(risk.reasons || []).join(",")}`) : "risk_auto_approved")
        : (autoApprovedTriple ? (tripleMatch.reason || "") : (autoApprovedPair ? "clientUuid+serverUuid pair matched" : "")),

      // ✅ Risk snapshot
      risk: risk ? { score: risk.score, tier: risk.tier, reasons: risk.reasons || [] } : null,

      ipMeta: {
        remoteAddr: ipInfo.remoteAddr,
        trustedProxy: ipInfo.trustedProxy,
        usedProxyHeader: ipInfo.usedProxyHeader,
        mode: TRUST_PROXY_MODE,
      },
    };

    if (autoApprovedFinal) {
      sessions[sid].openedAt = t;
    }

    await saveSessions();

    await appendAudit("ACCESS_REQUESTED", {
      sessionId: sid,
      clientUuid,
      serverUuid,
      clientIp: ip,
      assignedPort,
      expiresAt: sessions[sid].expiresAt,
      autoApproved: autoApprovedFinal,
      ttlSec: ttl,
      ipMeta: sessions[sid].ipMeta,

      // ✅ (추가) 정책 근거
      autoApprovedPolicy: sessions[sid].autoApprovedPolicy,
      autoApprovedRuleId: sessions[sid].autoApprovedRuleId,
      autoApprovedReason: sessions[sid].autoApprovedReason,
    });

    if (autoApprovedFinal) {
      await appendAudit("SESSION_AUTO_APPROVED", {
        sessionId: sid,
        clientUuid,
        serverUuid,
        assignedPort,
        clientIp: ip,
        expiresAt: sessions[sid].expiresAt,
        ttlSec: ttl,

        // ✅ (프롬프트7) 자동 승인도 감사로그에 정책/이유 남김
        policy: sessions[sid].autoApprovedPolicy,
        ruleId: sessions[sid].autoApprovedRuleId,
        reason: sessions[sid].autoApprovedReason,
        risk: sessions[sid].risk,
      });
    }

    res.json({
      ok: true,
      sessionId: sid,
      status,
      autoApproved: autoApprovedFinal,
      expiresAt: sessions[sid].expiresAt,
      reused: false,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// API: operator list sessions
// ==========================
app.get("/api/operator/sessions", operatorOrOidcAuth(["viewer","operator","admin"]), async (req, res) => {
  try {
    res.json({ ok: true, sessions });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// API: operator snapshot (light HA)
// - Creates a timestamped backup of data dir (registry/sessions/audit)
// ==========================
app.post("/api/operator/snapshot", operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    await ensureDataDir();
    const snapDir = path.join(DATA_DIR, "snapshots");
    await fsp.mkdir(snapDir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    const outPath = path.join(snapDir, `snapshot_${ts}.json`);
    const payload = {
      createdAt: new Date().toISOString(),
      files: {}
    };
    for (const fp of [REGISTRY_PATH, SESSIONS_PATH, AUDIT_LOG_PATH]) {
      if (fs.existsSync(fp)) {
        payload.files[path.basename(fp)] = await fsp.readFile(fp, "utf8");
      }
    }
    await fsp.writeFile(outPath, JSON.stringify(payload, null, 2), "utf8");
    await appendAudit("SNAPSHOT_CREATED", { file: path.basename(outPath) });
    res.json({ ok: true, snapshot: path.basename(outPath) });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});



// ==========================
// API: operator evidence export (Evidence Audit Bundle)
// - Creates evidence zip using built-in tar (Windows 10+ includes bsdtar)
// - Returns one-time download token (default TTL 60s)
// ==========================
const EVIDENCE_TOKEN_TTL_SEC = process.env.EVIDENCE_TOKEN_TTL_SEC ? parseInt(process.env.EVIDENCE_TOKEN_TTL_SEC, 10) : 60;
const EVIDENCE_DIR = path.join(DATA_DIR, "evidence");
const _evidenceTokens = new Map(); // token -> { filePath, expSec, used }

function _evidenceNowSec(){
  return Math.floor(Date.now()/1000);
}

function _evidenceRandToken(){
  return crypto.randomBytes(18).toString("base64url");
}

function _evidencePutToken(filePath){
  const t = _evidenceRandToken();
  _evidenceTokens.set(t, { filePath, expSec: _evidenceNowSec() + EVIDENCE_TOKEN_TTL_SEC, used: false });
  return t;
}

function _evidencePopToken(token){
  const rec = _evidenceTokens.get(token);
  if (!rec) return null;
  if (rec.used) return null;
  if (rec.expSec < _evidenceNowSec()) { _evidenceTokens.delete(token); return null; }
  rec.used = true;
  return rec;
}

function _sha256File(fp){
  const b = fs.readFileSync(fp);
  return crypto.createHash("sha256").update(b).digest("hex");
}

async function _copyIfExists(src, dst){
  try {
    if (!fs.existsSync(src)) return false;
    await fsp.copyFile(src, dst);
    return true;
  } catch { return false; }
}

function _listRecentLogFiles(dirPath, maxN){
  try {
    if (!fs.existsSync(dirPath)) return [];
    const items = fs.readdirSync(dirPath)
      .map(fn => {
        const full = path.join(dirPath, fn);
        let st;
        try { st = fs.statSync(full); } catch { return null; }
        if (!st.isFile()) return null;
        return { fn, full, mtimeMs: st.mtimeMs, size: st.size };
      })
      .filter(Boolean)
      .sort((a,b)=>(b.mtimeMs||0)-(a.mtimeMs||0));
    return items.slice(0, maxN || 3);
  } catch { return []; }
}

async function _runVerifyAudit(outDir){
  const verifyScript = path.join(__dirname, "audit", "verify_audit.cjs");
  const outPath = path.join(outDir, "verify_report.json");
  const args = [verifyScript, "--file", AUDIT_LOG_PATH];
  if (AUDIT_SIGNING_PUB_B64) args.push("--pub", AUDIT_SIGNING_PUB_B64);

  return new Promise((resolve) => {
    const cp = require("child_process");
    cp.execFile(process.execPath, args, { timeout: 15_000, windowsHide: true }, async (err, stdout, stderr) => {
      const payload = {
        ok: !err,
        ts: new Date().toISOString(),
        stdout: String(stdout || "").trim(),
        stderr: String(stderr || "").trim(),
        error: err ? (err.message || String(err)) : "",
      };
      try {
        await fsp.writeFile(outPath, JSON.stringify(payload, null, 2), "utf8");
      } catch (_) {}
      resolve(payload);
    });
  });
}

async function _makeEvidenceZip(sessionId, operatorId){
  await ensureDataDir();
  await fsp.mkdir(EVIDENCE_DIR, { recursive: true });

  const sid = String(sessionId || "").trim();
  if (!sid) throw new Error("missing_sessionId");

  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const tmpDir = path.join(EVIDENCE_DIR, `tmp_${sid}_${ts}`);
  await fsp.mkdir(tmpDir, { recursive: true });

  // 1) Copy core data
  await _copyIfExists(AUDIT_LOG_PATH, path.join(tmpDir, "audit.jsonl"));
  await _copyIfExists(SESSIONS_PATH, path.join(tmpDir, "sessions.json"));
  await _copyIfExists(REGISTRY_PATH, path.join(tmpDir, "registry.json"));

  // 2) Snapshot policy + context
  const policySnapshot = {
    createdAt: new Date().toISOString(),
    sessionId: sid,
    operatorId: String(operatorId || ""),
    app: { name: "GenieSecurity Relay", node: process.version },
    config: {
      RELAY_BASE: RELAY_BASE,
      TWO_MAN_RULE: !!TWO_MAN_RULE,
      DEFAULT_TTL_SEC: DEFAULT_TTL_SEC,
      EXTEND_TTL_SEC: EXTEND_TTL_SEC,
      MAX_OPENED_PER_SERVER: MAX_OPENED_PER_SERVER,
      SESSIONS_MAX: SESSIONS_MAX,
      FAIL_BLOCK_ENABLED: !!FAIL_BLOCK_ENABLED,
      AUDIT_REQUIRE_SIGNING: !!AUDIT_REQUIRE_SIGNING,
      AUDIT_SIGNING_KEY_ID: AUDIT_SIGNING_KEY_ID,
      AUDIT_REMOTE_URL: AUDIT_REMOTE_URL ? "(set)" : "",
    }
  };
  await fsp.writeFile(path.join(tmpDir, "policy_snapshot.json"), JSON.stringify(policySnapshot, null, 2), "utf8");

  // 3) Verify audit chain (writes verify_report.json)
  await _runVerifyAudit(tmpDir);

  // 4) Copy recent relay logs (best-effort)
  const recent = _listRecentLogFiles(path.join(__dirname, "logs"), 3);
  if (recent.length) {
    const logsDir = path.join(tmpDir, "relay_logs");
    await fsp.mkdir(logsDir, { recursive: true });
    for (const it of recent) {
      await _copyIfExists(it.full, path.join(logsDir, it.fn));
    }
  }

  // 5) Manifest (sha256)
  const files = [];
  function walk(dir, relBase=""){
    const items = fs.readdirSync(dir, { withFileTypes: true });
    for (const d of items) {
      const full = path.join(dir, d.name);
      const rel = relBase ? (relBase + "/" + d.name) : d.name;
      if (d.isDirectory()) walk(full, rel);
      else files.push({ path: rel, bytes: fs.statSync(full).size, sha256: _sha256File(full) });
    }
  }
  walk(tmpDir);
  const manifest = {
    createdAt: new Date().toISOString(),
    sessionId: sid,
    files,
  };
  await fsp.writeFile(path.join(tmpDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf8");

  // 6) Zip using tar -a (Windows bsdtar)
  const outName = `evidence_${sid}_${ts}.zip`;
  const outZip = path.join(EVIDENCE_DIR, outName);

  const cp = require("child_process");
  await new Promise((resolve, reject) => {
    const args = ["-a", "-c", "-f", outZip, "-C", tmpDir, "."];
    cp.execFile("tar", args, { windowsHide: true, timeout: 60_000 }, (err, stdout, stderr) => {
      if (err) {
        return reject(new Error(`tar_failed: ${String(stderr||stdout||err.message||err)}`));
      }
      resolve();
    });
  });

  // 7) Cleanup tmpDir (keep zip)
  try { await fsp.rm(tmpDir, { recursive: true, force: true }); } catch (_) {}

  return { outZip, outName };
}

app.post("/api/operator/evidence/export", requireSameOrigin, operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    const { sessionId } = req.body || {};
    const sid = String(sessionId || "").trim();
    if (!sid) return res.status(400).json({ ok: false, error: "missing_sessionId" });

    // best-effort existence check
    const exists = !!sessions[sid];
    await appendAudit("EVIDENCE_EXPORT_REQUESTED", { sessionId: sid, operatorId: req._operatorId || "" });

    const { outZip, outName } = await _makeEvidenceZip(sid, req._operatorId || "");
    await appendAudit("EVIDENCE_EXPORT_CREATED", { sessionId: sid, operatorId: req._operatorId || "", file: outName, sessionKnown: exists });

    const token = _evidencePutToken(outZip);
    return res.json({ ok: true, file: outName, downloadUrl: `/api/operator/evidence/download?token=${token}` });
  } catch (e) {
    await appendAudit("EVIDENCE_EXPORT_FAILED", { error: e.message || String(e) });
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

app.get("/api/operator/evidence/download", async (req, res) => {
  try {
    const token = String(req.query.token || "").trim();
    if (!token) return res.status(400).send("missing_token");
    const rec = _evidencePopToken(token);
    if (!rec) return res.status(404).send("invalid_or_expired_token");
    const fp = rec.filePath;
    if (!fp || !fs.existsSync(fp)) return res.status(404).send("file_missing");

    // Download
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename=\"${path.basename(fp)}\"`);
    fs.createReadStream(fp).pipe(res);
  } catch (e) {
    res.status(500).send("download_failed");
  }
});
// ==========================
// API: operator system status (for dashboard banners)
// ==========================
app.get("/api/operator/system", operatorOrOidcAuth(["viewer","operator","admin"]), async (req, res) => {
  try {
    const t = nowSec();
    res.json({
      ok: true,
      now: t,
      sessionsCount: Object.keys(sessions).length,
      purge: {
        intervalSec: SESSIONS_PURGE_INTERVAL_SEC,
        max: SESSIONS_MAX,
        expiredGraceSec: SESSIONS_PURGE_EXPIRED_GRACE_SEC,
        failGraceSec: SESSIONS_PURGE_FAIL_GRACE_SEC,
        last: LAST_PURGE,
      },
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


// ==========================
// API: operator approve open
// ==========================

// ==========================
// Policy Release APIs (Super5)
// - Lists versioned policy releases and allows activating one.
// - Requires admin (OIDC admin or operatorKey admin).
// ==========================
function listPolicyReleases() {
  const relDir = path.join(__dirname, "policy", "releases");
  const out = [];
  try {
    if (!fs.existsSync(relDir)) return out;
    for (const fn of fs.readdirSync(relDir)) {
      if (!fn.endsWith(".json")) continue;
      const full = path.join(relDir, fn);
      let st;
      try { st = fs.statSync(full); } catch (_) { continue; }
      out.push({ file: fn, size: st.size, mtimeMs: st.mtimeMs });
    }
  } catch (_) {}
  out.sort((a,b)=> (b.mtimeMs||0)-(a.mtimeMs||0));
  return out;
}

function readActivePolicyInfo() {
  const p = path.join(__dirname, "policy", "active_policy.json");
  try {
    if (!fs.existsSync(p)) return null;
    const b = fs.readFileSync(p);
    const h = crypto.createHash("sha256").update(b).digest("hex");
    return { exists: true, sha256: h, bytes: b.length };
  } catch (e) {
    return { exists: true, error: String(e && e.message ? e.message : e) };
  }
}

app.get("/api/operator/policies", operatorOrOidcAuth(["admin"]), async (req, res) => {
  return res.json({
    ok: true,
    active: readActivePolicyInfo(),
    releases: listPolicyReleases(),
  });
});

app.post("/api/operator/policies/set-active", operatorOrOidcAuth(["admin"]), async (req, res) => {
  try {
    const relFile = String((req.body && req.body.releaseFile) || "").trim();
    if (!relFile || !relFile.endsWith(".json") || relFile.includes("..") || relFile.includes("/") || relFile.includes("\\")) {
      return res.status(400).json({ ok: false, error: "bad_release_file" });
    }
    const relPath = path.join(__dirname, "policy", "releases", relFile);
    if (!fs.existsSync(relPath)) return res.status(404).json({ ok: false, error: "release_not_found" });

    const activePath = path.join(__dirname, "policy", "active_policy.json");
    const payload = fs.readFileSync(relPath);
    fs.writeFileSync(activePath, payload);

    // Copy signatures if present (single or dual)
    const sigs = [".sig", ".sig1", ".sig2"];
    for (const s of sigs) {
      const srcSig = relPath + s;
      const dstSig = activePath + s;
      try {
        if (fs.existsSync(srcSig)) fs.writeFileSync(dstSig, fs.readFileSync(srcSig));
      } catch (_) {}
    }

    // Audit
    auditLog("policy_activate", {
      actor: req.user ? { type: "oidc", sub: req.user.sub, email: req.user.email, name: req.user.name, role: req._operatorRole } : { type: "operatorKey", role: req._operatorRole },
      releaseFile: relFile,
    });

    return res.json({ ok: true, active: readActivePolicyInfo() });
  } catch (e) {
    console.error("[policy_activate] error:", e);
    return res.status(500).json({ ok: false, error: "internal_error" });
  }
});


app.post("/api/operator/approve-open", requireSameOrigin, operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    const { sessionId } = req.body || {};
    const s = sessions[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: "session_not_found" });


    // ✅ idempotency replay
    const idemKey = getIdemKey(req);
    if (idemKey) {
      const rec = idemLookup(s, "approve-open", idemKey);
      if (rec) return idemReplay(res, rec);
    }

    if (s.status !== "PENDING") {
      return res.json({ ok: false, error: "invalid_status", status: s.status });
    }

    
    // ✅ concurrency policy: limit OPENED sessions per server
    const openedCnt = countOpenedSessionsForServer(s.serverUuid);
    if (openedCnt >= MAX_OPENED_PER_SERVER) {
      return res.status(409).json({ ok: false, error: "server_opened_limit_reached", opened: openedCnt, max: MAX_OPENED_PER_SERVER });
    }

// ✅ 2-man rule (특허 강화 옵션)
// - TWO_MAN_RULE=1 이면 서로 다른 운영자 2명이 승인해야 OPENED로 전환
const opId = req._operatorId || "unknown";
s.openApprovals = Array.isArray(s.openApprovals) ? s.openApprovals : [];
if (!s.openApprovals.find(a => a && a.operatorId === opId)) {
  s.openApprovals.push({ operatorId: opId, at: nowSec() });
  await saveSessions();
  await appendAudit("OPEN_APPROVAL", { sessionId, serverUuid: s.serverUuid, operatorId: opId, approvals: s.openApprovals.map(x => x.operatorId) });
}

if (TWO_MAN_RULE) {
  const uniq = Array.from(new Set(s.openApprovals.map(x => x.operatorId)));
  if (uniq.length < 2) {
    return res.json({ ok: true, pendingSecond: true, approvals: uniq, status: s.status });
  }
}

s.status = "OPENED";
    s.openedAt = nowSec();

    // ✅ (추가) 운영자 승인에도 autoApproved 필드는 그대로 둘 수 있음(정보성)
    if (typeof s.autoApproved !== "boolean") s.autoApproved = false;

    await saveSessions();
    await appendAudit("SESSION_OPEN_APPROVED", {
      sessionId,
      clientUuid: s.clientUuid,
      serverUuid: s.serverUuid,
      clientIp: s.clientIp,
      assignedPort: s.assignedPort,
      expiresAt: s.expiresAt,
    });

    

    if (idemKey) { idemStore(s, "approve-open", idemKey, 200, { ok: true, sessionId, status: s.status, assignedPort: s.assignedPort, expiresAt: s.expiresAt }); saveSessions(); }
res.json({
      ok: true,
      sessionId,
      status: s.status,
      assignedPort: s.assignedPort,
      expiresAt: s.expiresAt,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ API: operator extend-session
// ==========================
app.post("/api/operator/extend-session", requireSameOrigin, operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    const { sessionId } = req.body || {};
    const s = sessions[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: "session_not_found" });


    // ✅ idempotency replay
    const idemKey = getIdemKey(req);
    if (idemKey) {
      const rec = idemLookup(s, "extend-session", idemKey);
      if (rec) return idemReplay(res, rec);
    }

    if (s.status !== "OPENED") {
      return res.json({ ok: false, error: "invalid_status", status: s.status });
    }

    const cnt = typeof s.extendCount === "number" ? s.extendCount : 0;
    if (cnt >= EXTEND_MAX_COUNT) {
      return res.json({ ok: false, error: "extend_limit_reached", extendCount: cnt, maxCount: EXTEND_MAX_COUNT });
    }

    if (EXTEND_ALLOW_ONLY_WHITELIST) {
      const allowed = isAutoApprovePair(s.clientUuid, s.serverUuid);
      if (!allowed) {
        return res.json({ ok: false, error: "extend_policy_denied" });
      }
    }

    const t = nowSec();
    const oldExpiresAt = s.expiresAt;

    const base = (typeof s.expiresAt === "number") ? Math.max(s.expiresAt, t) : t;

    s.extendCount = cnt + 1;
    s.extendedAt = t;
    s.expiresAt = base + EXTEND_SEC;

    delete s.warnedAt;

    s.openToken = undefined;
    s.openTokenIssuedAt = undefined;
    s.openTokenJti = undefined;

    await saveSessions();

    await appendAudit("SESSION_EXTENDED", {
      sessionId,
      serverUuid: s.serverUuid,
      clientUuid: s.clientUuid,
      assignedPort: s.assignedPort,
      clientIp: s.clientIp,
      oldExpiresAt,
      newExpiresAt: s.expiresAt,
      extendCount: s.extendCount,
      extendSec: EXTEND_SEC,
    });

    res.json({
      ok: true,
      sessionId,
      status: s.status,
      extendCount: s.extendCount,
      expiresAt: s.expiresAt,
      extendedAt: s.extendedAt,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// API: operator reject
// ==========================
app.post("/api/operator/reject", requireSameOrigin, operatorOrOidcAuth(["operator","admin"]), async (req, res) => {
  try {
    const { sessionId } = req.body || {};
    const s = sessions[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: "session_not_found" });


    // ✅ idempotency replay
    const idemKey = getIdemKey(req);
    if (idemKey) {
      const rec = idemLookup(s, "reject", idemKey);
      if (rec) return idemReplay(res, rec);
    }

    if (s.status !== "PENDING") {
      return res.json({ ok: false, error: "invalid_status", status: s.status });
    }

    s.status = "REJECTED";
    s.rejectedAt = nowSec();

    await saveSessions();
    await appendAudit("SESSION_REJECTED", { sessionId });

    res.json({ ok: true, sessionId, status: s.status });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ API: server confirm-open
// ==========================
app.post("/api/server/confirm-open", async (req, res) => {
  try {
    // Step2: serverToken 제거 (공개키 기반)
    const { serverUuid, kid } = req.body || {};
    if (!serverUuid || !kid) return res.status(400).json({ ok: false, error: "missing_fields" });

// ==========================


    const srv = servers[serverUuid];
    if (!srv || !srv.pub || !srv.kid) {
      await appendAudit("CONFIRM_OPEN_BLOCKED", { serverUuid, reason: "server_missing_identity" });
      return res.status(403).json({ ok: false, error: "server_missing_identity" });
    }
    if (String(srv.status || "").toUpperCase() !== "ACTIVE") {
      await appendAudit("CONFIRM_OPEN_BLOCKED", { serverUuid, reason: "server_not_active", status: srv.status || "" });
      return res.status(403).json({ ok: false, error: "server_not_active" });
    }
    if (String(srv.kid) !== String(kid)) {
      await appendAudit("CONFIRM_OPEN_BLOCKED", { serverUuid, reason: "kid_mismatch", kid: String(kid), regKid: String(srv.kid) });
      return res.status(403).json({ ok: false, error: "kid_mismatch" });
    }

    const s = findConsumableOpenedSessionForServer(serverUuid);

    if (!s) {
      await appendAudit("CONFIRM_OPEN_BLOCKED", {
        serverUuid,
        reason: "no_consumable_opened_session",
      });
      return res.status(409).json({ ok: false, error: "no_consumable_opened_session" });
    }

    // 이미 consumed 된 세션이면 재발급 금지
    if (typeof s.consumedAt === "number") {
      await appendAudit("CONFIRM_OPEN_REPLAY", { serverUuid, sessionId: s.sessionId, consumedAt: s.consumedAt });
      return res.status(409).json({ ok: false, error: "confirm_open_already_consumed" });
    }

    // KEM 발급 (서버 공개키로만 복호화 가능)
    const t = nowSec();
    const exp = (typeof s.expiresAt === "number") ? s.expiresAt : (t + DEFAULT_OPEN_TTL_SEC);
    const jti = crypto.randomBytes(16).toString("hex");

    const payload = {
      sid: s.sessionId,
      serverUuid: s.serverUuid,
      clientIp: s.clientIp,
      assignedPort: s.assignedPort,
      expiresAt: s.expiresAt,
      extendCount: s.extendCount || 0,
      iat: t,
      exp,
      jti,
      v: "open.v2",
    };

    const srvPubKey = x25519PublicKeyFromRawB64(srv.pub);
    const eph = x25519GenEphemeral();
    const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: srvPubKey });

    const salt = crypto.randomBytes(16);
    const okm = hkdfSha256(shared, salt, "GenieSecurity.confirm-open.v2", 64);
    const keyEnc = okm.slice(0, 32);
    const keyMac = okm.slice(32, 64);

    const aad = Buffer.from(`confirm-open|${serverUuid}|${kid}|${payload.sid}|${jti}`, "utf8");
    const enc = aes256gcmEncrypt(keyEnc, Buffer.from(JSON.stringify(payload), "utf8"), aad);

    const challenge = crypto.randomBytes(16);
    const challengeB64 = bufToB64(challenge);

    const mac = crypto
      .createHmac("sha256", keyMac)
      .update(`confirm-open:${challengeB64}:${jti}`, "utf8")
      .digest("base64");

    // pending 저장 (메모리 only)
    pendingConsumes[jti] = {
      serverUuid,
      sessionId: payload.sid,
      kid: String(kid),
      ephPrivRawB64: eph.privRawB64,
      ephPubRawB64: eph.pubRawB64,
      saltB64: bufToB64(salt),
      ivB64: bufToB64(enc.iv),
      tagB64: bufToB64(enc.tag),
      ctB64: bufToB64(enc.ciphertext),
      challengeB64,
      macB64: mac,
      expSec: exp,
      createdAt: t,
    };

    await appendAudit("CONFIRM_OPEN_KEM_ISSUED", {
      serverUuid,
      sessionId: payload.sid,
      exp,
      jti,
      kid: String(kid),
    });

    // NOTE: 여기서는 consumed 처리하지 않음.
    // consume-open에서 PoP 검증 성공 시에만 consumedAt 세팅.
    res.json({
      ok: true,
      kem: {
        v: "kem.v1",
        kid: String(kid),
        ephPub: eph.pubRawB64,
        salt: bufToB64(salt),
        iv: bufToB64(enc.iv),
        tag: bufToB64(enc.tag),
        ct: bufToB64(enc.ciphertext),
        aad: bufToB64(aad),
      },
      challenge: challengeB64,
      mac,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// ✅ Step2: consume-open (PoP 검증 후 1회 소비)
// body: { serverUuid, kid, jti, challenge, sig, proof }
// sig = Ed25519 signature(base64) over canonical message
// proof = legacy HMAC proof (deprecated)
// ==========================
app.post("/api/server/consume-open", async (req, res) => {
  try {
    const { serverUuid, kid, jti, challenge, sig, proof } = req.body || {};
    if (!serverUuid || !kid || !jti || !challenge || (!sig && !proof)) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    const pend = pendingConsumes[jti];
    if (!pend || pend.serverUuid !== serverUuid || pend.kid !== String(kid) || pend.challengeB64 !== String(challenge)) {
      await appendAudit("CONSUME_OPEN_BLOCKED", { serverUuid, jti: String(jti), reason: "pending_not_found_or_mismatch" });
      return res.status(409).json({ ok: false, error: "pending_not_found" });
    }

    const srv = servers[serverUuid];
    if (!srv || !srv.pub || String(srv.kid) !== String(kid)) {
      await appendAudit("CONSUME_OPEN_BLOCKED", { serverUuid, jti: String(jti), reason: "server_identity_missing" });
      return res.status(403).json({ ok: false, error: "server_missing_identity" });
    }

    const sess = sessions[pend.sessionId];
    if (!sess) {
      delete pendingConsumes[jti];
      await appendAudit("CONSUME_OPEN_BLOCKED", { serverUuid, sessionId: pend.sessionId, jti: String(jti), reason: "session_not_found" });
      return res.status(404).json({ ok: false, error: "session_not_found" });
    }

    if (typeof sess.consumedAt === "number") {
      delete pendingConsumes[jti];
      await appendAudit("CONSUME_OPEN_REPLAY", { serverUuid, sessionId: sess.sessionId, consumedAt: sess.consumedAt, jti: String(jti) });
      return res.status(409).json({ ok: false, error: "already_consumed" });
    }

    // ✅ S-1: Server-only consumption proof
    // - Preferred: Ed25519 signature PoP (sig)
    // - Backward compatible: HMAC proof (proof) for older agents
    if (!srv.sigPub) {
      await appendAudit("CONSUME_OPEN_BLOCKED", { serverUuid, sessionId: sess.sessionId, jti: String(jti), reason: "server_sigpub_missing" });
      return res.status(403).json({ ok: false, error: "server_missing_sigpub" });
    }

    if (sig) {
      // Ed25519 verify
      const pubKey = ed25519PublicKeyFromRawB64(srv.sigPub);
      const msg = Buffer.from(
        `GenieSecurity/consume-open/v1
${String(serverUuid)}
${String(kid)}
${String(sess.sessionId)}
${String(jti)}
${String(challenge)}
`,
        "utf8"
      );
      const sigBuf = Buffer.from(String(sig), "base64");

      const okSig = crypto.verify(null, msg, pubKey, sigBuf);
      if (!okSig) {
        await appendAudit("CONSUME_OPEN_BLOCKED", { serverUuid, sessionId: sess.sessionId, jti: String(jti), reason: "sig_invalid" });
        return res.status(403).json({ ok: false, error: "sig_invalid" });
      }
    } else {
      // Legacy HMAC proof path (should be removed after full migration)
      const srvPubKey = x25519PublicKeyFromRawB64(srv.pub);
      const ephPrivKey = x25519PrivateKeyFromRawB64(pend.ephPrivRawB64);
      const shared = crypto.diffieHellman({ privateKey: ephPrivKey, publicKey: srvPubKey });

      const salt = Buffer.from(String(pend.saltB64), "base64");
      const okm = hkdfSha256(shared, salt, "GenieSecurity.confirm-open.v2", 64);
      const keyMac = okm.slice(32, 64);

      const expected = crypto
        .createHmac("sha256", keyMac)
        .update(`consume-open:${String(challenge)}:${String(jti)}`, "utf8")
        .digest("base64");

      if (!timingSafeEqualB64(expected, proof)) {
        await appendAudit("CONSUME_OPEN_BLOCKED", { serverUuid, sessionId: sess.sessionId, jti: String(jti), reason: "proof_invalid" });
        return res.status(403).json({ ok: false, error: "proof_invalid" });
      }
    }

    // ✅ 여기서 1회 소비 확정
    sess.consumedAt = nowSec();
    await saveSessions();

    delete pendingConsumes[jti];

    await appendAudit("CONFIRM_OPEN_CONSUMED", {
      serverUuid,
      sessionId: sess.sessionId,
      assignedPort: sess.assignedPort,
      clientIp: sess.clientIp,
      expiresAt: sess.expiresAt,
      consumedAt: sess.consumedAt,
      jti: String(jti),
    });

    res.json({ ok: true, sessionId: sess.sessionId, consumedAt: sess.consumedAt });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});



// ==========================
// ✅ (NEW) API: server session-status (server_agent용)
// - 목적: Extend/Expire 상태를 server_agent가 주기적으로 조회하여 실제 방화벽 open/close를 Relay 기준으로 동기화
// - 기존 로직 변경 없음 (읽기 전용)
// body: { serverUuid, serverToken, sessionId }
// resp: { ok:true, session:{ sessionId, status, expiresAt, assignedPort, clientIp, extendCount, consumedAt } }
app.post("/api/server/session-status", async (req, res) => {
  try {
    const { serverUuid, sessionId } = req.body || {};
    if (!serverUuid || !sessionId) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    const s = sessions[sessionId];
    if (!s) return res.status(404).json({ ok: false, error: "session_not_found" });

    if (s.serverUuid !== serverUuid) {
      return res.status(403).json({ ok: false, error: "serverUuid_mismatch" });
    }

    // ✅ 보안: 만료 tick이 아직 돌기 전이라도, 여기서 현재시간 기준 만료 상태를 즉시 계산해 반환(읽기 전용)
    const t = nowSec();
    let status = s.status;
    if (status !== "EXPIRED" && status !== "REJECTED") {
      if (typeof s.expiresAt === "number" && s.expiresAt <= t) {
        status = "EXPIRED";
      }
    }

    return res.json({
      ok: true,
      ts: t,
      session: {
        sessionId: s.sessionId,
        status,
        expiresAt: s.expiresAt,
        assignedPort: s.assignedPort,
        clientIp: s.clientIp,
        extendCount: s.extendCount || 0,
        consumedAt: s.consumedAt,
      },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});


// ==========================
// ✅ (NEW) API: server fail-block
// ==========================
app.post("/api/server/fail-block", async (req, res) => {
  try {
    const { serverUuid, sessionId, reason, meta } = req.body || {};
    if (!serverUuid || !sessionId) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    const s = sessions[sessionId];

    if (!s) {
      await appendAudit("FAIL_BLOCK_REPORTED", {
        serverUuid,
        sessionId,
        reason: reason || "fail_block",
        meta: meta || {},
        result: "session_not_found",
      });
      return res.json({ ok: true });
    }

    if (s.serverUuid !== serverUuid) {
      await appendAudit("FAIL_BLOCK_REPORTED", {
        serverUuid,
        sessionId,
        reason: reason || "fail_block",
        meta: meta || {},
        result: "serverUuid_mismatch",
        sessionServerUuid: s.serverUuid,
      });
      return res.json({ ok: true });
    }

    await forceCloseEnforced(sessionId, s, reason || "fail_block", meta || {});
    res.json({ ok: true });
  } catch (e) {
    await appendAudit("FAIL_BLOCK_API_ERROR", { error: e.message });
    res.json({ ok: true }); // 정보 최소화
  }
});

// ==========================
// API: server report firewall
// ==========================

// Command log ingest (HMAC-signed, fail-closed on signature when key set)
const REPORT_INGEST_HMAC_B64 = process.env.REPORT_INGEST_HMAC_B64 || "";
function _hmacVerify(b64Key, bodyBuf, sigB64){
  try{
    const key = Buffer.from(b64Key, "base64");
    const mac = crypto.createHmac("sha256", key).update(bodyBuf).digest("base64");
    return crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(String(sigB64||"")));
  }catch(_){ return false; }
}
app.post("/api/report/command-log", express.json({ limit: "512kb" }), async (req, res) => {
  try {
    const rawBody = Buffer.from(JSON.stringify(req.body || {}), "utf8");
    const sig = req.header("X-Genie-Signature") || "";
    if (REPORT_INGEST_HMAC_B64) {
      if (!sig || !_hmacVerify(REPORT_INGEST_HMAC_B64, rawBody, sig)) {
        await appendAudit("COMMAND_LOG_REJECTED", { reason: "bad_signature" });
        return res.status(401).json({ ok: false, error: "bad_signature" });
      }
    }
    const payload = req.body || {};
    const sid = String(payload.sid || "unknown");
    const entry = {
      ts: nowSec(),
      iso: new Date().toISOString(),
      sid,
      source: String(payload.source || ""),
      host: String(payload.host || ""),
      user: String(payload.user || ""),
      record: payload.record || null,
    };

    const outDir = path.join(LOGS_DIR, "command_logs", sid);
    await fsp.mkdir(outDir, { recursive: true });
    const outPath = path.join(outDir, "command_logs.jsonl");
    await fsp.appendFile(outPath, JSON.stringify(entry) + "\n", "utf8");

    await appendAudit("COMMAND_LOG_INGESTED", { sid, source: entry.source, host: entry.host, user: entry.user });
    return res.json({ ok: true });
  } catch (e) {
    try { await appendAudit("COMMAND_LOG_INGEST_ERROR", { error: String(e && e.message || e) }); } catch(_) {}
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

// RDP recording ingest (binary, HMAC-signed over body, fail-closed on signature when key set)
const REPORT_MAX_BYTES = parseInt(process.env.REPORT_MAX_BYTES || "262144000", 10); // 250MB
app.post("/api/report/rdp-recording", express.raw({ type: "application/octet-stream", limit: REPORT_MAX_BYTES }), async (req, res) => {
  try {
    const sid = String(req.header("X-Genie-Sid") || "unknown");
    const filename = String(req.header("X-Genie-Filename") || "recording.bin").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 160);
    const sig = req.header("X-Genie-Signature") || "";
    const bodyBuf = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || "");

    if (REPORT_INGEST_HMAC_B64) {
      if (!sig || !_hmacVerify(REPORT_INGEST_HMAC_B64, bodyBuf, sig)) {
        await appendAudit("RDP_RECORDING_REJECTED", { sid, reason: "bad_signature", filename });
        return res.status(401).json({ ok: false, error: "bad_signature" });
      }
    }

    const outDir = path.join(LOGS_DIR, "rdp_recordings", sid);
    await fsp.mkdir(outDir, { recursive: true });
    const outPath = path.join(outDir, filename);
    await fsp.writeFile(outPath, bodyBuf);

    // Minimal manifest line for indexing
    const manifestPath = path.join(outDir, "manifest.jsonl");
    const entry = { ts: nowSec(), iso: new Date().toISOString(), sid, filename, bytes: bodyBuf.length };
    await fsp.appendFile(manifestPath, JSON.stringify(entry) + "\n", "utf8");

    await appendAudit("RDP_RECORDING_INGESTED", { sid, filename, bytes: bodyBuf.length });
    return res.json({ ok: true });
  } catch (e) {
    try { await appendAudit("RDP_RECORDING_INGEST_ERROR", { error: String(e && e.message || e) }); } catch(_) {}
    return res.status(500).json({ ok: false, error: "server_error" });
  }
});

app.post("/api/server/report-firewall", async (req, res) => {
  try {
    const { serverUuid, event, sessionId, assignedPort, ruleName, message, remoteIp } = req.body || {};

    needUuid(serverUuid, "serverUuid");
    needStr(sid, "sid", 128);
    needStr(status, "status", 32);
    if (!serverUuid || !event) {
      return res.status(400).json({ ok: false, error: "missing_fields" });
    }

    // Always keep raw report (for debugging / forensics)
    await appendAudit("SERVER_FIREWALL_REPORT", {
      serverUuid,
      event,
      sessionId,
      assignedPort,
      ruleName,
      message,
      remoteIp,
    });

    // Normalize event types from agents (support aliases)
    const ev = String(event || "").toLowerCase();

    // If we can link to a session, persist + append session-level audit so Dashboard cards fill.
    const sid = (sessionId || "").trim();
    const s = sid ? sessions[sid] : null;

    if (s) {
      // persist fields for UI
      if (assignedPort !== undefined) s.assignedPort = s.assignedPort ?? assignedPort;
      if (ruleName) s.ruleName = ruleName;
      if (remoteIp) s.clientIp = s.clientIp ?? remoteIp; // note: dashboard column uses clientIp
      s.lastFirewallEventAt = nowSec();

      if (ev === "FIREWALL_OPEN_OK" || ev === "FIREWALL_OPENED") {
        s.firewallOpenedAt = nowSec();
        await appendAudit("FIREWALL_OPEN", {
          sessionId: sid,
          serverUuid,
          assignedPort,
          ruleName,
          remoteIp,
          message,
        });
      }

      if (ev === "FIREWALL_CLOSE_OK" || ev === "FIREWALL_CLOSED" || ev === "FIREWALL_CLOSED_OK" || ev === "FIREWALL_CLOSED_DONE") {
        s.firewallClosedAt = nowSec();
        if (typeof s.closeEnforcedAt === "number" && typeof s.closeEnforcedDoneAt !== "number") {
          s.closeEnforcedDoneAt = nowSec();
        }
        await appendAudit("FIREWALL_CLOSED", {
          sessionId: sid,
          serverUuid,
          assignedPort,
          ruleName,
          remoteIp,
          message,
        });
      }

      // best-effort persist
      await saveSessions();
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// API: server poll-command
// ==========================
app.post("/api/server/poll-command", async (req, res) => {
  try {
    const { serverUuid } = req.body || {};
    if (!serverUuid) return res.status(400).json({ ok: false, error: "missing_fields" });

    const q = commands[serverUuid] || [];
    if (q.length === 0) return res.json({ ok: true, command: null });

    const cmd = q.shift();
    await appendAudit("COMMAND_POLLED", { serverUuid, cmd });

    res.json({ ok: true, command: cmd });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// API: session detail
// ==========================
app.get("/api/session/:sid", async (req, res) => {
  try {
    const sid = req.params.sid;
    const s = sessions[sid];
    if (!s) return res.status(404).json({ ok: false, error: "session_not_found" });
    

    if (idemKey) { idemStore(s, "extend-session", idemKey, 200, { ok: true, sessionId, status: s.status, expiresAt: s.expiresAt, extendCount: s.extendCount }); saveSessions(); }


    if (idemKey) { idemStore(s, "reject", idemKey, 200, { ok: true, sessionId, status: s.status }); saveSessions(); }


    if (idemKey) { idemStore(s, "approve-server", idemKey, 200, { ok: true, serverUuid, status: s.status }); saveRegistry(); }
res.json({ ok: true, session: s });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ==========================
// start server
// ==========================
// ==========================
// ✅ Troubleshooting: error codes catalog
// ==========================
app.get("/api/troubleshooting/codes", (req, res) => {
  return res.json({ ok: true, codes: ERROR_CATALOG, requestId: req.requestId });
});

// TLS / mTLS (optional)
const TLS_KEY_PATH = String(process.env.TLS_KEY_PATH || '').trim();
const TLS_CERT_PATH = String(process.env.TLS_CERT_PATH || '').trim();
const TLS_CA_PATH = String(process.env.TLS_CA_PATH || '').trim();
const MTLS_REQUIRE = String(process.env.MTLS_REQUIRE || '0').trim() === '1';
const MTLS_CLIENT_FINGERPRINTS = String(process.env.MTLS_CLIENT_FINGERPRINTS || '').split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

function _loadPemMaybe(pth){
  try{
    if (!pth) return null;
    const abs = path.isAbsolute(pth) ? pth : path.join(ROOT_DIR, pth);
    if (!fs.existsSync(abs)) return null;
    return fs.readFileSync(abs);
  } catch(_) { return null; }
}


function startServer() {
  const host = process.env.RELAY_BIND_HOST || '127.0.0.1';
  const port = PORT;

  const keyPem = _loadPemMaybe(TLS_KEY_PATH);
  const certPem = _loadPemMaybe(TLS_CERT_PATH);
  const caPem = _loadPemMaybe(TLS_CA_PATH);

  if (keyPem && certPem) {
    const https = require('https');
    const opts = { key: keyPem, cert: certPem };
    if (caPem) opts.ca = caPem;
    if (MTLS_REQUIRE) {
      opts.requestCert = true;
      // If CA is provided, let Node validate peer cert chain.
      // If CA is NOT provided, we still capture the cert and enforce fingerprint allowlist in mtlsGate.
      opts.rejectUnauthorized = !!caPem;
    }
    const srv = https.createServer(opts, app);
    srv.listen(port, host, () => {
      console.log(` Relay Server (HTTPS) listening on https://${host}:${port}`);
      console.log(` Dashboard on https://${host}:${port}/`);
      if (MTLS_REQUIRE) console.log(' mTLS: REQUIRED');
    });
    return;
  }

  app.listen(port, host, () => {
    console.log(` Relay Server listening on http://${host}:${port}`);
    console.log(` Dashboard on http://${host}:${port}/`);
  });
}

startServer();
  // ✅ (Policy) clean up stale enforced-close "in progress" sessions on boot
  const tNow = nowSec();
  let changed = false;
  for (const sid of Object.keys(sessions)) {
    const s = sessions[sid];
    if (!s) continue;
    if (typeof s.closeEnforcedAt !== "number") continue;
    if (typeof s.closeEnforcedDoneAt === "number") continue;
    if (typeof s.firewallClosedAt === "number") {
      s.closeEnforcedDoneAt = s.firewallClosedAt;
      s.closeEnforcedDoneReason = "firewall_closed_reported";
      changed = true;
      continue;
    }
    if ((tNow - s.closeEnforcedAt) >= ENFORCED_CLOSE_TIMEOUT_SEC) {
      s.closeEnforcedDoneAt = tNow;
      s.closeEnforcedDoneReason = "timeout_cleanup";
      changed = true;
    }
  }
  if (changed) {
    console.log(` [BOOT] enforced-close stale sessions marked done (timeout=${ENFORCED_CLOSE_TIMEOUT_SEC}s)`);
  }

// === JSON parse fail-safe (safe, final) ===
app.use((err, req, res, next) => {
  if (err && err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.error('[JSON_PARSE_ERROR]', err.message);
    return res.status(400).json({ error: 'Invalid JSON payload' });
  }
  next(err);
});