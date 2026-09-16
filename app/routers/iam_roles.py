"""IAM 角色管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.iam_role import RoleCreate, RoleUpdate
from app.services.iam_role import RoleService

router = APIRouter(prefix="/api/iam/roles", tags=["iam-roles"])


@router.get("")
async def list_roles(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RoleService.list_roles(session, limit=limit, offset=offset)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_role(
    payload: RoleCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RoleService.create_role(session, payload, request)


@router.get("/{role_id}")
async def get_role(
    role_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RoleService.get_role(session, role_id)


@router.patch("/{role_id}")
async def update_role(
    role_id: str, payload: RoleUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RoleService.update_role(session, role_id, payload, request)


@router.delete("/{role_id}")
async def delete_role(
    role_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await RoleService.delete_role(session, role_id, request)
