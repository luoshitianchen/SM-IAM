"""IAM 角色仓储层。"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.iam_role import IAMRole


async def get_role(session: AsyncSession, role_id: str) -> IAMRole | None:
    result = await session.execute(select(IAMRole).where(IAMRole.id == role_id))
    return result.scalar_one_or_none()


async def get_role_by_name(session: AsyncSession, name: str) -> IAMRole | None:
    result = await session.execute(select(IAMRole).where(IAMRole.name == name))
    return result.scalar_one_or_none()


async def list_roles(session: AsyncSession, limit: int = 100, offset: int = 0) -> list[IAMRole]:
    result = await session.execute(select(IAMRole).order_by(IAMRole.created_at.desc()).limit(limit).offset(offset))
    return list(result.scalars().all())


async def count_roles(session: AsyncSession) -> int:
    result = await session.execute(select(func.count(IAMRole.id)))
    return result.scalar_one()


async def create_role(session: AsyncSession, role: IAMRole) -> IAMRole:
    session.add(role)
    await session.commit()
    await session.refresh(role)
    return role


async def update_role(session: AsyncSession, role: IAMRole) -> IAMRole:
    await session.commit()
    await session.refresh(role)
    return role


async def delete_role(session: AsyncSession, role: IAMRole) -> None:
    await session.delete(role)
    await session.commit()
