"""IAM 用户管理路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.iam_user import UserCreate, UserPasswordChange, UserStatusUpdate, UserUpdate
from app.services.iam_user import UserService

router = APIRouter(prefix="/api/iam/users", tags=["iam-users"])


@router.get("")
async def list_users(
    request: Request,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.list_users(session, limit=limit, offset=offset, status_filter=status_filter)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.create_user(session, payload, request)


@router.get("/{user_id}")
async def get_user(
    user_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.get_user(session, user_id)


@router.patch("/{user_id}")
async def update_user(
    user_id: str, payload: UserUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.update_user(session, user_id, payload, request)


@router.patch("/{user_id}/status")
async def update_user_status(
    user_id: str, payload: UserStatusUpdate, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.update_status(session, user_id, payload.status, request)


@router.post("/{user_id}/password")
async def change_password(
    user_id: str, payload: UserPasswordChange, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.change_password(session, user_id, payload.old_password,
                                              payload.new_password, request)


@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: str, request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    return await UserService.delete_user(session, user_id, request)
