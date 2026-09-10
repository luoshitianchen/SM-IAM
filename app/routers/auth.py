"""OAuth2/OIDC 认证路由（SM-IAM 特有）。"""
from __future__ import annotations

import json
import secrets
import time
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from sqlalchemy import String, Text, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.core.config import settings
from app.core.database import get_session
from app.core.security import sign_jwt, sm3_hex, verify_jwt
from app.models.base import Base

router = APIRouter(tags=["auth"])


class IAMUser(Base):
    __tablename__ = "iam_users"
    username: Mapped[str] = mapped_column(String(128), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    roles: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[str] = mapped_column(String(64), default="")


class IAMClient(Base):
    __tablename__ = "iam_clients"
    client_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_secret_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[str] = mapped_column(String(64), default="")


async def _ensure_seed(session: AsyncSession) -> None:
    result = await session.execute(select(IAMUser).limit(1))
    if not result.scalar_one_or_none():
        password = settings.IAM_BOOTSTRAP_PASSWORD or "ChangeMe123!"
        session.add(IAMUser(
            username=settings.IAM_BOOTSTRAP_USER, password_hash=sm3_hex(password),
            display_name="系统管理员", roles=json.dumps(["admin"], ensure_ascii=False),
            created_at=datetime.now(UTC).isoformat(),
        ))
    result = await session.execute(select(IAMClient).limit(1))
    if not result.scalar_one_or_none():
        client_secret = settings.IAM_BOOTSTRAP_CLIENT_SECRET or secrets.token_urlsafe(32)
        session.add(IAMClient(
            client_id=settings.IAM_BOOTSTRAP_CLIENT_ID,
            client_secret_hash=sm3_hex(client_secret),
            scopes=json.dumps(["openid", "profile", "roles"], ensure_ascii=False),
            created_at=datetime.now(UTC).isoformat(),
        ))
    await session.commit()


@router.post("/oauth/token")
async def oauth_token(
    request: Request, grant_type: str = Form(...),
    client_id: str = Form(default=""), client_secret: str = Form(default=""),
    username: str = Form(default=""), password: str = Form(default=""),
    session: AsyncSession = Depends(get_session),
) -> dict:
    await _ensure_seed(session)
    if grant_type == "client_credentials":
        result = await session.execute(select(IAMClient).where(IAMClient.client_id == client_id))
        client = result.scalar_one_or_none()
        if not client or not secrets.compare_digest(client.client_secret_hash, sm3_hex(client_secret)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "客户端凭据无效")
        subject, roles, scopes = f"client:{client_id}", ["client"], json.loads(client.scopes or "[]")
    elif grant_type == "password":
        result = await session.execute(select(IAMUser).where(IAMUser.username == username))
        user = result.scalar_one_or_none()
        if not user or not secrets.compare_digest(user.password_hash, sm3_hex(password)):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "用户名或密码错误")
        subject, roles = username, json.loads(user.roles or "[]")
        scopes = ["openid", "profile", "roles"]
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "不支持的 grant_type")

    now = int(time.time())
    claims = {
        "iss": settings.SERVICE_NAME, "sub": subject, "aud": "sm-services",
        "iat": now, "exp": now + settings.JWT_TTL_SECONDS,
        "scope": " ".join(scopes), "roles": roles,
    }
    token = sign_jwt(claims)
    return {
        "access_token": token, "token_type": "Bearer",
        "expires_in": settings.JWT_TTL_SECONDS, "scope": " ".join(scopes),
    }


@router.get("/oidc/.well-known/openid-configuration")
async def oidc_configuration(request: Request) -> dict:
    base = str(request.base_url).rstrip("/")
    return {
        "issuer": base, "authorization_endpoint": f"{base}/oauth/token",
        "token_endpoint": f"{base}/oauth/token", "jwks_uri": f"{base}/oidc/jwks",
        "scopes_supported": ["openid", "profile", "roles"],
        "grant_types_supported": ["password", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "response_types_supported": ["token"],
    }


@router.get("/oidc/jwks")
async def oidc_jwks() -> dict:
    from app.core.security import _jwt_secret, b64url
    key = _jwt_secret().encode()
    return {"keys": [{
        "kty": "oct", "use": "sig", "alg": "HS256",
        "kid": sm3_hex(_jwt_secret())[:16], "k": b64url(key),
    }]}


@router.get("/api/auth/me")
async def auth_me(request: Request) -> dict:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "缺少 Bearer Token")
    claims = verify_jwt(authorization[7:])
    if not claims:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token 无效或已过期")
    return {
        "sub": claims["sub"], "roles": claims.get("roles", []),
        "scope": claims.get("scope", ""),
        "expires_in": max(0, int(claims["exp"]) - int(time.time())),
    }
