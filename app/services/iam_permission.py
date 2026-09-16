"""IAM 权限服务层。"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories import iam_permission as repo


class PermissionService:
    @staticmethod
    async def list_permissions(session: AsyncSession, resource: str | None = None,
                                limit: int = 200, offset: int = 0) -> dict:
        perms = await repo.list_permissions(session, resource=resource, limit=limit, offset=offset)
        return {
            "total": len(perms),
            "items": [
                {"code": p.code, "description": p.description,
                 "resource": p.resource, "action": p.action}
                for p in perms
            ],
        }
