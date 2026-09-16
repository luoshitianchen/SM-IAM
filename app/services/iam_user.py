"""IAM 用户服务层：全生命周期管理。"""
from __future__ import annotations

import json
import re
import secrets
import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed, sm3_hex
from app.models.iam_user import IAMUser
from app.repositories import iam_user as repo
from app.schemas.iam_user import UserCreate, UserUpdate
from app.services.audit import record_audit

PASSWORD_PATTERN = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$")


def _validate_password(password: str) -> None:
    if not PASSWORD_PATTERN.match(password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "密码须至少8位且包含大小写字母和数字")


def _user_to_dict(u: IAMUser) -> dict:
    return {
        "id": u.id, "username": u.username, "display_name": u.display_name,
        "email": u.email or "", "status": u.status,
        "roles": json.loads(u.roles or "[]"),
        "failed_login_count": u.failed_login_count,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else "",
        "updated_at": u.updated_at.isoformat() if u.updated_at else "",
    }


class UserService:
    @staticmethod
    async def list_users(session: AsyncSession, limit: int = 100, offset: int = 0,
                         status_filter: str | None = None) -> dict:
        users = await repo.list_users(session, limit=limit, offset=offset, status=status_filter)
        total = await repo.count_users(session, status=status_filter)
        return {"total": total, "items": [_user_to_dict(u) for u in users]}

    @staticmethod
    async def get_user(session: AsyncSession, user_id: str) -> dict:
        user = await repo.get_user(session, user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
        return _user_to_dict(user)

    @staticmethod
    async def create_user(session: AsyncSession, payload: UserCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        _validate_password(payload.password)
        if await repo.get_user_by_username(session, payload.username):
            raise HTTPException(status.HTTP_409_CONFLICT, "用户名已存在")
        user = IAMUser(
            id=str(uuid.uuid4()), username=payload.username,
            password_hash=sm3_hex(payload.password),
            display_name=payload.display_name, email=payload.email or "",
            roles=json.dumps(payload.roles, ensure_ascii=False),
            status="active",
        )
        user = await repo.create_user(session, user)
        await record_audit(session, "user.created", "internal",
                           f"username={payload.username}", request)
        return _user_to_dict(user)

    @staticmethod
    async def update_user(session: AsyncSession, user_id: str, payload: UserUpdate,
                          request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        user = await repo.get_user(session, user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
        if payload.display_name is not None:
            user.display_name = payload.display_name
        if payload.email is not None:
            user.email = payload.email
        if payload.roles is not None:
            user.roles = json.dumps(payload.roles, ensure_ascii=False)
        user = await repo.update_user(session, user)
        await record_audit(session, "user.updated", "internal",
                           f"user_id={user_id}", request)
        return _user_to_dict(user)

    @staticmethod
    async def update_status(session: AsyncSession, user_id: str, new_status: str,
                            request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        user = await repo.get_user(session, user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
        user.status = new_status
        if new_status == "active":
            user.failed_login_count = 0
        user = await repo.update_user(session, user)
        await record_audit(session, "user.status_changed", "internal",
                           f"user_id={user_id} status={new_status}", request)
        return _user_to_dict(user)

    @staticmethod
    async def change_password(session: AsyncSession, user_id: str, old_password: str,
                              new_password: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        user = await repo.get_user(session, user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
        if not secrets.compare_digest(user.password_hash, sm3_hex(old_password)):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "原密码错误")
        _validate_password(new_password)
        user.password_hash = sm3_hex(new_password)
        user = await repo.update_user(session, user)
        await record_audit(session, "user.password_changed", "internal",
                           f"user_id={user_id}", request)
        return {"id": user.id, "username": user.username, "password_changed": True}

    @staticmethod
    async def delete_user(session: AsyncSession, user_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        user = await repo.get_user(session, user_id)
        if not user:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "用户不存在")
        username = user.username
        await repo.delete_user(session, user)
        await record_audit(session, "user.deleted", "internal",
                           f"user_id={user_id} username={username}", request)
        return {"deleted": True, "id": user_id}
