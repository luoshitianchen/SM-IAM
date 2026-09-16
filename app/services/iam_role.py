"""IAM 角色服务层。"""
from __future__ import annotations

import json
import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import internal_write_allowed
from app.models.iam_role import IAMRole
from app.repositories import iam_role as repo
from app.schemas.iam_role import RoleCreate, RoleUpdate
from app.services.audit import record_audit


def _role_to_dict(r: IAMRole) -> dict:
    return {
        "id": r.id, "name": r.name, "description": r.description,
        "permissions": json.loads(r.permissions or "[]"),
        "is_system": r.is_system,
        "created_at": r.created_at.isoformat() if r.created_at else "",
    }


class RoleService:
    @staticmethod
    async def list_roles(session: AsyncSession, limit: int = 100, offset: int = 0) -> dict:
        roles = await repo.list_roles(session, limit=limit, offset=offset)
        total = await repo.count_roles(session)
        return {"total": total, "items": [_role_to_dict(r) for r in roles]}

    @staticmethod
    async def get_role(session: AsyncSession, role_id: str) -> dict:
        role = await repo.get_role(session, role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "角色不存在")
        return _role_to_dict(role)

    @staticmethod
    async def create_role(session: AsyncSession, payload: RoleCreate, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        if await repo.get_role_by_name(session, payload.name):
            raise HTTPException(status.HTTP_409_CONFLICT, "角色名已存在")
        role = IAMRole(
            id=str(uuid.uuid4()), name=payload.name, description=payload.description,
            permissions=json.dumps(payload.permissions, ensure_ascii=False),
            is_system=False,
        )
        role = await repo.create_role(session, role)
        await record_audit(session, "role.created", "internal",
                           f"name={payload.name}", request)
        return _role_to_dict(role)

    @staticmethod
    async def update_role(session: AsyncSession, role_id: str, payload: RoleUpdate,
                          request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        role = await repo.get_role(session, role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "角色不存在")
        if payload.description is not None:
            role.description = payload.description
        if payload.permissions is not None:
            role.permissions = json.dumps(payload.permissions, ensure_ascii=False)
        role = await repo.update_role(session, role)
        await record_audit(session, "role.updated", "internal",
                           f"role_id={role_id}", request)
        return _role_to_dict(role)

    @staticmethod
    async def delete_role(session: AsyncSession, role_id: str, request: Request) -> dict:
        if not internal_write_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "内部写入令牌无效")
        role = await repo.get_role(session, role_id)
        if not role:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "角色不存在")
        if role.is_system:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "系统角色不可删除")
        name = role.name
        await repo.delete_role(session, role)
        await record_audit(session, "role.deleted", "internal",
                           f"role_id={role_id} name={name}", request)
        return {"deleted": True, "id": role_id}
