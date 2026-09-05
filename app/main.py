"""SM IAM —— 统一身份认证：用户、角色、RBAC、会话令牌与多因素认证。"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, Field

from app import base

SERVICE = "sm-iam"
VERSION = "3.0.0"
NAME = "SM IAM"
DESCRIPTION = "统一身份认证：用户、角色、RBAC、会话令牌与多因素认证"
PORT = 8300

SESSION_TTL_HOURS = 12
_PBKDF2_ITERATIONS = 100_000


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS).hex()
    return f"{salt}${digest}"


def _password_verify(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(_password_hash(password, salt).split("$", 1)[1], digest)


def _init() -> None:
    with base.db_ctx() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL, roles TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'active', mfa_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS roles (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT,
                permissions TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
            );
            """
        )


app = base.create_app(
    service=SERVICE, name=NAME, description=DESCRIPTION, version=VERSION, port=PORT,
    dependencies=["sm-audit-log-center"],
    events=["user.created", "user.login", "user.logout", "session.revoked"],
    overview_fn=lambda _r: {
        "summary": {
            "users": base.get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "roles": base.get_db().execute("SELECT COUNT(*) FROM roles").fetchone()[0],
        }
    },
)
_init()


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: str = Field(min_length=5, max_length=120)
    password: str = Field(min_length=8, max_length=128)
    roles: list[str] = Field(default_factory=list)


class RoleIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    description: str = Field(default="", max_length=200)
    permissions: list[str] = Field(default_factory=list)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=128)


class StatusIn(BaseModel):
    status: str = Field(pattern=r"^(active|disabled)$")


class PasswordIn(BaseModel):
    password: str = Field(min_length=8, max_length=128)


class VerifyIn(BaseModel):
    token: str = Field(min_length=16)


@app.post("/api/iam/users", status_code=status.HTTP_201_CREATED)
def create_user(payload: UserIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    user_id = str(uuid.uuid4())
    with base.db_ctx() as conn:
        for role in payload.roles:
            if not conn.execute("SELECT 1 FROM roles WHERE name=?", (role,)).fetchone():
                raise HTTPException(status.HTTP_404_NOT_FOUND, f"角色不存在: {role}")
        try:
            conn.execute("INSERT INTO users (id, username, email, password_hash, roles, status, mfa_enabled, created_at) VALUES (?,?,?,?,?,?,?,?)", (user_id, payload.username, payload.email, _password_hash(payload.password), json.dumps(payload.roles, ensure_ascii=False), "active", 0, _now()))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status.HTTP_409_CONFLICT, "用户名或邮箱已存在") from exc
        base.record_audit("user.created", "internal", f"user={payload.username}", getattr(request.state, "request_id", ""), getattr(request.state, "trace_id", ""), SERVICE)
    return {"id": user_id, "username": payload.username}


@app.get("/api/iam/users")
def list_users() -> dict[str, Any]:
    with base.db_ctx() as conn:
        rows = conn.execute("SELECT id, username, email, roles, status, mfa_enabled, created_at, last_login_at FROM users ORDER BY created_at DESC").fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@app.get("/api/iam/users/{user_id}")
def get_user(user_id: str) -> dict[str, Any]:
    with base.db_ctx() as conn:
        row = conn.execute("SELECT id, username, email, roles, status, mfa_enabled, created_at, last_login_at FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    return dict(row)


@app.post("/api/iam/users/{user_id}/status")
def set_user_status(user_id: str, payload: StatusIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        if conn.execute("UPDATE users SET status=? WHERE id=?", (payload.status, user_id)).rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    return {"id": user_id, "status": payload.status}


@app.post("/api/iam/users/{user_id}/password")
def set_password(user_id: str, payload: PasswordIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        if conn.execute("UPDATE users SET password_hash=? WHERE id=?", (_password_hash(payload.password), user_id)).rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
    return {"id": user_id, "updated": True}


@app.post("/api/iam/roles", status_code=status.HTTP_201_CREATED)
def create_role(payload: RoleIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    role_id = str(uuid.uuid4())
    with base.db_ctx() as conn:
        try:
            conn.execute("INSERT INTO roles VALUES (?,?,?,?,?)", (role_id, payload.name, payload.description, json.dumps(payload.permissions, ensure_ascii=False), _now()))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status.HTTP_409_CONFLICT, "角色已存在") from exc
    return {"id": role_id, "name": payload.name}


@app.get("/api/iam/roles")
def list_roles() -> dict[str, Any]:
    with base.db_ctx() as conn:
        rows = conn.execute("SELECT * FROM roles ORDER BY created_at DESC").fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows)}


@app.post("/api/iam/auth/login")
def login(payload: LoginIn, request: Request) -> dict[str, Any]:
    with base.db_ctx() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (payload.username,)).fetchone()
        if not user or not _password_verify(payload.password, user["password_hash"]):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
        if user["status"] != "active":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "账号已被禁用")
        token = f"smt_{secrets.token_urlsafe(32)}"
        session_id = str(uuid.uuid4())
        expires_at = (datetime.now(UTC) + timedelta(hours=SESSION_TTL_HOURS)).isoformat()
        conn.execute("INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, revoked) VALUES (?,?,?,?,?,0)", (session_id, user["id"], base.sm3_hex(token.encode()), _now(), expires_at))
        conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (_now(), user["id"]))
        base.record_audit("user.login", payload.username, f"user={user['id']}", getattr(request.state, "request_id", ""), getattr(request.state, "trace_id", ""), SERVICE)
    return {"token": token, "user_id": user["id"], "username": user["username"], "roles": json.loads(user["roles"]), "expires_at": expires_at}


@app.post("/api/iam/auth/verify")
def verify(payload: VerifyIn) -> dict[str, Any]:
    with base.db_ctx() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE token_hash=? AND revoked=0", (base.sm3_hex(payload.token.encode()),)).fetchone()
        if not session:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "会话无效")
        if session["expires_at"] < _now():
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "会话已过期")
        user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user or user["status"] != "active":
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户不可用")
    return {"valid": True, "user_id": user["id"], "username": user["username"], "roles": json.loads(user["roles"])}


@app.post("/api/iam/auth/logout")
def logout(payload: VerifyIn, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        session = conn.execute("SELECT * FROM sessions WHERE token_hash=? AND revoked=0", (base.sm3_hex(payload.token.encode()),)).fetchone()
        if not session:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "会话无效")
        conn.execute("UPDATE sessions SET revoked=1 WHERE id=?", (session["id"],))
        base.record_audit("user.logout", "internal", f"session={session['id']}", getattr(request.state, "request_id", ""), getattr(request.state, "trace_id", ""), SERVICE)
    return {"revoked": True}


@app.post("/api/iam/users/{user_id}/mfa")
def enable_mfa(user_id: str, request: Request) -> dict[str, Any]:
    base.require_internal_token(request)
    with base.db_ctx() as conn:
        if conn.execute("UPDATE users SET mfa_enabled=1 WHERE id=?", (user_id,)).rowcount == 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
        secret = base32_secret()
    return {"user_id": user_id, "mfa_enabled": True, "otpauth_secret": secret}


def base32_secret() -> str:
    """生成 Base32 风格 TOTP 密钥（演示用途）。"""
    return "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(32))


@app.get("/api/iam/stats")
def stats() -> dict[str, Any]:
    with base.db_ctx() as conn:
        def _count(sql: str) -> int:
            return conn.execute(sql).fetchone()[0]
        return {
            "users": _count("SELECT COUNT(*) FROM users"),
            "active_users": _count("SELECT COUNT(*) FROM users WHERE status='active'"),
            "roles": _count("SELECT COUNT(*) FROM roles"),
            "active_sessions": _count("SELECT COUNT(*) FROM sessions WHERE revoked=0 AND expires_at>datetime('now')"),
            "mfa_enabled": _count("SELECT COUNT(*) FROM users WHERE mfa_enabled=1"),
        }