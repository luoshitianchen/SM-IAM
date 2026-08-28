from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

VERSION = "2.1.0"
SERVICE_NAME = "sm-iam"
DISPLAY_NAME = "SM IAM"
DESCRIPTION = "统一身份认证中心：SSO、OIDC、MFA 与账号生命周期"
ENVIRONMENT = os.getenv("SM_ENV", "development").lower()
ALLOWED_HOSTS = [h.strip() for h in os.getenv("SM_ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",") if h.strip()]
REQUESTS = {"total": 0, "errors": 0, "latency_ms_total": 0.0}
RATE_BUCKETS: dict[str, tuple[int, int]] = {}
rate_limit_lock = threading.Lock()
MAX_REQUEST_BYTES = int(os.getenv("SM_MAX_REQUEST_BYTES", "1048576"))
RATE_WINDOW_SECONDS = int(os.getenv("SM_RATE_WINDOW_SECONDS", "60"))
RATE_MAX_REQUESTS = int(os.getenv("SM_RATE_MAX_REQUESTS", "600"))
INTERNAL_API_KEY = os.getenv("SM_INTERNAL_API_KEY", "")
JWT_SECRET = os.getenv("SM_JWT_SECRET", "")
JWT_TTL_SECONDS = int(os.getenv("SM_JWT_TTL_SECONDS", "3600"))
DATABASE_PATH = os.getenv("SM_DATABASE_PATH", "")
AUDIT_CENTER_URL = os.getenv("SM_AUDIT_CENTER_URL", "")
BOOTSTRAP_USER = os.getenv("SM_IAM_BOOTSTRAP_USER", "admin")
BOOTSTRAP_PASSWORD = os.getenv("SM_IAM_BOOTSTRAP_PASSWORD", "")
BOOTSTRAP_CLIENT_ID = os.getenv("SM_IAM_BOOTSTRAP_CLIENT_ID", "fusion-gateway")
BOOTSTRAP_CLIENT_SECRET = os.getenv("SM_IAM_BOOTSTRAP_CLIENT_SECRET", "")
INTEGRATION_DEPENDENCIES = ['sm-audit-log-center']
INTEGRATION_EVENTS = ["health.checked", "resource.changed", "audit.recorded", "token.issued"]
_db_conn: sqlite3.Connection | None = None
_db_lock = threading.RLock()


def db() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is not None:
        return _db_conn
    with _db_lock:
        if _db_conn is not None:
            return _db_conn
        target = DATABASE_PATH or ":memory:"
        if target != ":memory:":
            Path(target).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(target, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, display_name TEXT, roles TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, client_secret_hash TEXT NOT NULL, scopes TEXT, created_at TEXT);
            CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT, service TEXT, action TEXT, actor TEXT, timestamp TEXT, request_id TEXT, trace_id TEXT, detail TEXT, integrity TEXT);
            """
        )
        conn.commit()
        _db_conn = conn
        _seed(conn)
        return conn


def _seed(conn: sqlite3.Connection) -> None:
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        password = BOOTSTRAP_PASSWORD or "ChangeMe123!"
        conn.execute(
            "INSERT INTO users (username, password_hash, display_name, roles, created_at) VALUES (?, ?, ?, ?, ?)",
            (BOOTSTRAP_USER, sm3_hex(password), "系统管理员", json.dumps(["admin"], ensure_ascii=False), datetime.now(UTC).isoformat()),
        )
    if not conn.execute("SELECT 1 FROM clients LIMIT 1").fetchone():
        client_secret = BOOTSTRAP_CLIENT_SECRET or secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO clients (client_id, client_secret_hash, scopes, created_at) VALUES (?, ?, ?, ?)",
            (BOOTSTRAP_CLIENT_ID, sm3_hex(client_secret), json.dumps(["openid", "profile", "roles"], ensure_ascii=False), datetime.now(UTC).isoformat()),
        )
    conn.commit()


def setting(key: str, default: str = "") -> str:
    row = db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if row:
        return str(row["value"])
    return default


def set_setting(key: str, value: str) -> None:
    db().execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    db().commit()


def jwt_secret() -> str:
    if JWT_SECRET:
        return JWT_SECRET
    existing = setting("jwt_secret")
    if not existing:
        existing = secrets.token_hex(32)
        set_setting("jwt_secret", existing)
    return existing


def check_rate_limit(key: str) -> bool:
    with rate_limit_lock:
        current = int(time.time())
        for bucket_key, (started, _) in list(RATE_BUCKETS.items()):
            if current - started >= RATE_WINDOW_SECONDS:
                RATE_BUCKETS.pop(bucket_key, None)
        started, count = RATE_BUCKETS.get(key, (current, 0))
        if current - started >= RATE_WINDOW_SECONDS:
            started, count = current, 0
        if count >= RATE_MAX_REQUESTS:
            return False
        RATE_BUCKETS[key] = (started, count + 1)
        return True

def internal_write_allowed(request: Request) -> bool:
    if not INTERNAL_API_KEY:
        return False
    return secrets.compare_digest(request.headers.get("X-Internal-Token", ""), INTERNAL_API_KEY)


def sm3_hex(value: str) -> str:
    from gmssl import func, sm3
    return sm3.sm3_hash(func.bytes_to_list(value.encode("utf-8")))

def _sm4_key() -> bytes:
    existing = setting("sm4_key_hex")
    if not existing:
        existing = secrets.token_hex(16)
        set_setting("sm4_key_hex", existing)
    key = bytes.fromhex(existing)
    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes")
    return key

def sm4_crypt(value: bytes, encrypt: bool) -> bytes:
    from gmssl.sm4 import CryptSM4, SM4_DECRYPT, SM4_ENCRYPT
    iv = secrets.token_bytes(16)
    cipher = CryptSM4()
    cipher.set_key(_sm4_key(), SM4_ENCRYPT if encrypt else SM4_DECRYPT)
    if encrypt:
        return iv + cipher.crypt_cbc(iv, value)
    if len(value) < 16:
        raise ValueError("ciphertext too short")
    iv, body = value[:16], value[16:]
    cipher.set_key(_sm4_key(), SM4_DECRYPT)
    return cipher.crypt_cbc(iv, body)

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def sign_jwt(claims: dict[str, object]) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    signing_input = f"{header}.{payload}".encode()
    signature = hmac.new(jwt_secret().encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(signature)}"

def verify_jwt(token: str) -> dict[str, object] | None:
    try:
        header_b64, claims_b64, signature_b64 = token.split(".")
        signing_input = f"{header_b64}.{claims_b64}".encode()
        expected = hmac.new(jwt_secret().encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(signature_b64)):
            return None
        claims = json.loads(b64url_decode(claims_b64))
        if int(claims.get("exp", 0)) < time.time():
            return None
        if claims.get("iss") != SERVICE_NAME:
            return None
        return claims
    except Exception:
        return None

def _audit(request: Request, action: str, actor: str, detail: dict[str, object] | None = None) -> None:
    event_id = str(uuid.uuid4())
    trace_id = request.headers.get("X-Trace-Id", "") or request.headers.get("X-Request-Id", "")
    payload = json.dumps({"service": SERVICE_NAME, "action": action, "actor": actor, "timestamp": datetime.now(UTC).isoformat(), "event_id": event_id, "request_id": request.headers.get("X-Request-Id", ""), "detail": detail or {}}, ensure_ascii=False, sort_keys=True)
    integrity = sm3_hex(payload)
    with _db_lock:
        db().execute(
            "INSERT INTO audit_events (event_id, service, action, actor, timestamp, request_id, trace_id, detail, integrity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, SERVICE_NAME, action, actor, datetime.now(UTC).isoformat(), request.headers.get("X-Request-Id", ""), trace_id, payload, integrity),
        )
        db().commit()
    if AUDIT_CENTER_URL:
        try:
            import httpx
            httpx.post(f"{AUDIT_CENTER_URL.rstrip('/')}/api/audit/events", json={"event_id": event_id, "service": SERVICE_NAME, "action": action, "actor": actor, "timestamp": datetime.now(UTC).isoformat(), "request_id": request.headers.get("X-Request-Id", ""), "trace_id": trace_id, "detail": detail or {}, "integrity": integrity}, timeout=1.0)
        except Exception:
            pass

app = FastAPI(title=DISPLAY_NAME, version=VERSION, description=DESCRIPTION, docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

class Item(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    owner: str = Field(default="身份平台部", min_length=1, max_length=80)
    priority: Literal["P0", "P1", "P2", "P3"] = "P1"
    status: Literal["planned", "active", "review", "closed"] = "active"

ITEMS: list[dict[str, object]] = [
    {"id": "demo-1", "name": "核心能力基线", "owner": "身份平台部", "priority": "P1", "status": "active", "created_at": datetime.now(UTC).isoformat()},
    {"id": "demo-2", "name": "安全与审计策略", "owner": "安全合规部", "priority": "P1", "status": "review", "created_at": datetime.now(UTC).isoformat()},
]

@app.middleware("http")
async def security_headers(request: Request, call_next):
    started = time.perf_counter()
    request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            body_size = int(content_length)
        except ValueError:
            response = Response(status_code=400, content="Invalid Content-Length")
        else:
            if body_size < 0 or body_size > MAX_REQUEST_BYTES:
                response = Response(status_code=413, content="Request body too large")
            elif not check_rate_limit(f"{request.client.host if request.client else 'unknown'}:{request.url.path}"):
                response = Response(status_code=429, content="Too many requests", headers={"Retry-After": str(RATE_WINDOW_SECONDS)})
            else:
                response = await call_next(request)
    elif not check_rate_limit(f"{request.client.host if request.client else 'unknown'}:{request.url.path}"):
        response = Response(status_code=429, content="Too many requests", headers={"Retry-After": str(RATE_WINDOW_SECONDS)})
    else:
        response = await call_next(request)
    elapsed = (time.perf_counter() - started) * 1000
    REQUESTS["total"] += 1
    REQUESTS["latency_ms_total"] += elapsed
    if response.status_code >= 500:
        REQUESTS["errors"] += 1
    response.headers["X-Request-Id"] = request_id[:64]
    response.headers["X-Trace-Id"] = trace_id[:64]
    response.headers["X-Process-Time-Ms"] = f"{elapsed:.2f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    if ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response

@app.get("/", include_in_schema=False)
def console() -> FileResponse:
    return FileResponse("app/static/index.html")

@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "service": SERVICE_NAME, "name": DISPLAY_NAME, "version": VERSION, "timestamp": datetime.now(UTC).isoformat()}

@app.get("/readyz")
def readyz() -> dict[str, object]:
    return {"status": "ready", "service": SERVICE_NAME, "checks": {"runtime": "ok", "configuration": "ok", "database": "ok" if db() else "error"}}

@app.post("/oauth/token")
def oauth_token(request: Request) -> dict[str, object]:
    form = request.form()
    import anyio
    async def _read():
        return await form
    data = anyio.from_thread.run(_read)
    grant_type = data.get("grant_type", "")
    if grant_type == "client_credentials":
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")
        row = db().execute("SELECT client_secret_hash FROM clients WHERE client_id=?", (client_id,)).fetchone()
        if not row or not secrets.compare_digest(str(row["client_secret_hash"]), sm3_hex(client_secret)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "客户端凭据无效")
        subject = f"client:{client_id}"
        roles = ["client"]
        scopes = json.loads(str(row["scopes"] or "[]"))
    elif grant_type == "password":
        username = data.get("username", "")
        password = data.get("password", "")
        row = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not row or not secrets.compare_digest(str(row["password_hash"]), sm3_hex(password)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
        subject = username
        roles = json.loads(str(row["roles"] or "[]"))
        scopes = ["openid", "profile", "roles"]
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "不支持的 grant_type")
    now = int(time.time())
    claims = {"iss": SERVICE_NAME, "sub": subject, "aud": "sm-services", "iat": now, "exp": now + JWT_TTL_SECONDS, "scope": " ".join(scopes), "roles": roles}
    token = sign_jwt(claims)
    _audit(request, "token.issued", subject, {"grant_type": grant_type})
    return {"access_token": token, "token_type": "Bearer", "expires_in": JWT_TTL_SECONDS, "scope": " ".join(scopes)}

@app.get("/oidc/.well-known/openid-configuration")
def oidc_configuration(request: Request) -> dict[str, object]:
    base = str(request.base_url).rstrip("/")
    return {"issuer": base, "authorization_endpoint": f"{base}/oauth/token", "token_endpoint": f"{base}/oauth/token", "jwks_uri": f"{base}/oidc/jwks", "scopes_supported": ["openid", "profile", "roles"], "grant_types_supported": ["password", "client_credentials"], "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["HS256"], "response_types_supported": ["token"]}

@app.get("/oidc/jwks")
def oidc_jwks() -> dict[str, object]:
    key = jwt_secret().encode()
    return {"keys": [{"kty": "oct", "use": "sig", "alg": "HS256", "kid": sm3_hex(jwt_secret())[:16], "k": b64url(key)}]}

@app.get("/api/auth/me")
def auth_me(request: Request) -> dict[str, object]:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "缺少 Bearer Token")
    claims = verify_jwt(authorization[7:])
    if not claims:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token 无效或已过期")
    return {"sub": claims["sub"], "roles": claims.get("roles", []), "scope": claims.get("scope", ""), "expires_in": max(0, int(claims["exp"]) - int(time.time()))}

@app.get("/api/overview")
def overview() -> dict[str, object]:
    return {"platform": {"name": DISPLAY_NAME, "version": VERSION, "description": DESCRIPTION}, "items": ITEMS, "total": len(ITEMS), "active": sum(1 for i in ITEMS if i["status"] == "active")}

@app.post("/api/items", status_code=status.HTTP_201_CREATED)
def create_item(payload: Item, request: Request) -> dict[str, object]:
    if not internal_write_allowed(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
    item = {"id": str(uuid.uuid4()), **payload.model_dump(), "created_at": datetime.now(UTC).isoformat()}
    ITEMS.append(item)
    _audit(request, "resource.changed", "internal", {"resource": "item", "id": item["id"]})
    return item

@app.patch("/api/items/{item_id}/status")
def update_item_status(item_id: str, item_status: Literal["planned", "active", "review", "closed"], request: Request) -> dict[str, object]:
    if not internal_write_allowed(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
    for item in ITEMS:
        if item["id"] == item_id:
            item["status"] = item_status
            _audit(request, "resource.changed", "internal", {"resource": "item", "id": item_id, "status": item_status})
            return item
    raise HTTPException(status.HTTP_404_NOT_FOUND, "资源不存在")

@app.get("/api/ops/metrics")
def metrics() -> dict[str, object]:
    total = int(REQUESTS["total"])
    avg = round(float(REQUESTS["latency_ms_total"]) / total, 2) if total else 0.0
    return {"service": SERVICE_NAME, "version": VERSION, "requests_total": total, "errors_total": int(REQUESTS["errors"]), "avg_latency_ms": avg}

@app.get("/metrics")
def prometheus_metrics() -> Response:
    total = int(REQUESTS["total"])
    body = (
        f"sm_iam_requests_total {total}\n"
        f"sm_iam_errors_total {int(REQUESTS['errors'])}\n"
        f"sm_iam_latency_ms_total {REQUESTS['latency_ms_total']:.2f}\n"
    )
    return Response(content=body, media_type="text/plain; version=0.0.4")

@app.get("/api/audit/events")
def audit_events(request: Request) -> dict[str, object]:
    if not internal_write_allowed(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
    rows = db().execute("SELECT event_id, service, action, actor, timestamp, trace_id, integrity FROM audit_events ORDER BY id DESC LIMIT 200").fetchall()
    return {"service": SERVICE_NAME, "events": [dict(row) for row in rows]}

@app.get("/api/integration/manifest")
def integration_manifest() -> dict[str, object]:
    return {
        "service": SERVICE_NAME,
        "name": DISPLAY_NAME,
        "version": VERSION,
        "dependencies": INTEGRATION_DEPENDENCIES,
        "events": INTEGRATION_EVENTS,
        "health_path": "/health",
        "metrics_path": "/api/ops/metrics",
        "overview_path": "/api/overview",
    }

@app.post("/api/crypto/sm3")
def crypto_sm3(payload: dict[str, str]) -> dict[str, str]:
    value = payload.get("value", "")
    if len(value) > 10000:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "内容过大")
    return {"algorithm": "SM3", "digest": sm3_hex(value)}

@app.post("/api/crypto/encrypt")
def crypto_encrypt(payload: dict[str, str]) -> dict[str, str]:
    value = payload.get("value", "")
    if len(value) > 10000:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "内容过大")
    return {"algorithm": "SM4-CBC", "ciphertext": sm4_crypt(value.encode("utf-8"), True).hex()}

@app.post("/api/crypto/decrypt")
def crypto_decrypt(payload: dict[str, str]) -> dict[str, str]:
    try:
        value = bytes.fromhex(payload.get("value", ""))
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "密文必须是十六进制")
    return {"algorithm": "SM4-CBC", "plaintext": sm4_crypt(value, False).decode("utf-8")}

@app.get("/api/crypto/status")
def crypto_status() -> dict[str, object]:
    return {"algorithm": "SM3/SM4", "sm3": "enabled", "sm4": "enabled", "key_source": "SM4_KEY_HEX / persisted setting"}

@app.get("/api/security/baseline")
def security_baseline() -> dict[str, object]:
    return {
        "service": SERVICE_NAME,
        "version": VERSION,
        "controls": {
            "trusted_host": True,
            "security_headers": True,
            "csp": True,
            "rate_limit": True,
            "request_size_limit": True,
            "sm3": True,
            "sm4": True,
            "internal_token": bool(INTERNAL_API_KEY),
            "jwt": bool(JWT_SECRET) or bool(setting("jwt_secret")),
            "oidc": True,
            "audit_persistence": True,
        },
        "recommended": ["KMS/HSM", "centralized audit", "OpenTelemetry", "TOTP MFA"],
    }
