"""IAM 权限仓储层。"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.iam_permission import IAMPermission


async def list_permissions(session: AsyncSession, resource: str | None = None,
                            limit: int = 200, offset: int = 0) -> list[IAMPermission]:
    stmt = select(IAMPermission).order_by(IAMPermission.code).limit(limit).offset(offset)
    if resource:
        stmt = stmt.where(IAMPermission.resource == resource)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_permission(session: AsyncSession, code: str) -> IAMPermission | None:
    result = await session.execute(select(IAMPermission).where(IAMPermission.code == code))
    return result.scalar_one_or_none()


async def create_permission(session: AsyncSession, perm: IAMPermission) -> IAMPermission:
    session.add(perm)
    await session.commit()
    await session.refresh(perm)
    return perm
