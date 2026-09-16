"""IAM 权限管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.iam_permission import PermissionService

router = APIRouter(prefix="/api/iam/permissions", tags=["iam-permissions"])


@router.get("")
async def list_permissions(
    request: Request,
    resource: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await PermissionService.list_permissions(session, resource=resource,
                                                      limit=limit, offset=offset)
