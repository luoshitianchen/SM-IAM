"""IAM 客户端仓储层。"""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.iam_client import IAMClient


async def get_client(session: AsyncSession, client_id: str) -> IAMClient | None:
    result = await session.execute(select(IAMClient).where(IAMClient.client_id == client_id))
    return result.scalar_one_or_none()


async def list_clients(session: AsyncSession, limit: int = 100, offset: int = 0,
                       status: str | None = None) -> list[IAMClient]:
    stmt = select(IAMClient).order_by(IAMClient.created_at.desc()).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(IAMClient.status == status)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_clients(session: AsyncSession) -> int:
    result = await session.execute(select(func.count(IAMClient.client_id)))
    return result.scalar_one()


async def create_client(session: AsyncSession, client: IAMClient) -> IAMClient:
    session.add(client)
    await session.commit()
    await session.refresh(client)
    return client


async def update_client(session: AsyncSession, client: IAMClient) -> IAMClient:
    await session.commit()
    await session.refresh(client)
    return client


async def delete_client(session: AsyncSession, client: IAMClient) -> None:
    await session.delete(client)
    await session.commit()
