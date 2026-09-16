"""IAM 用户仓储层。"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.iam_user import IAMUser


async def get_user(session: AsyncSession, user_id: str) -> IAMUser | None:
    result = await session.execute(select(IAMUser).where(IAMUser.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_username(session: AsyncSession, username: str) -> IAMUser | None:
    result = await session.execute(select(IAMUser).where(IAMUser.username == username))
    return result.scalar_one_or_none()


async def list_users(session: AsyncSession, limit: int = 100, offset: int = 0,
                     status: str | None = None) -> list[IAMUser]:
    stmt = select(IAMUser).order_by(IAMUser.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(IAMUser.status == status)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_users(session: AsyncSession, status: str | None = None) -> int:
    stmt = select(func.count(IAMUser.id))
    if status:
        stmt = stmt.where(IAMUser.status == status)
    result = await session.execute(stmt)
    return result.scalar_one()


async def create_user(session: AsyncSession, user: IAMUser) -> IAMUser:
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def update_user(session: AsyncSession, user: IAMUser) -> IAMUser:
    await session.commit()
    await session.refresh(user)
    return user


async def delete_user(session: AsyncSession, user: IAMUser) -> None:
    await session.delete(user)
    await session.commit()
